//! Create-only Stado release publisher for verified Jeden build handoffs.
//! Signing keys and the dedicated Stado publisher bearer stay on the trusted host.

use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::{Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::core::vault::Vault;

const PAYLOAD_TYPE: &str = "application/vnd.jeden.release-manifest.v2+json";
const REPOSITORY: &str = "Wisent-AI/jeden";
const PRODUCT: &str = "jeden";
const TARGETS: &[&str] = &["x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-pc-windows-msvc"];

struct Authority { key_id: String, signing_key: SigningKey }
struct Candidate { version:String, target: String, archive_name:String, archive_file:File, files: BTreeMap<String,Vec<u8>>, digests: BTreeMap<String,String> }

struct StadoPublisher { base_url:String, authorization:String, agent:ureq::Agent }

impl Drop for StadoPublisher { fn drop(&mut self){self.authorization.zeroize();} }
#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct BuildHandoff { schema:String, repository:String, head_sha:String, version:String, minimum_version:String, created_at:String, contractual_ci_run_id:String, contractual_ci_run_attempt:u64, build_run_id:String, build_run_attempt:u64, target_triple:String, artifact:ArtifactRef, sbom:EvidenceRef, provenance:EvidenceRef }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRef { name:String, sha256:String, size:u64 }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRef { name:String, sha256:String }
#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct GateRecord { schema:String, head_sha:String, contractual_ci_run_id:String, contractual_ci_run_attempt:u64, reports:GateReports }
#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct GateReports { interface_equivalence:EvidenceRef, migration_matrix:EvidenceRef }

fn hash(bytes: &[u8]) -> String { format!("{:x}",Sha256::digest(bytes)) }
fn decimal(value: &str) -> bool { !value.is_empty() && value != "0" && !value.starts_with('0') && value.bytes().all(|b|b.is_ascii_digit()) }
fn lower_hex(value: &str, size: usize) -> bool { value.len()==size && value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) }
fn coordinate(value:&str)->bool{!value.is_empty()&&value.bytes().all(|byte|byte.is_ascii_alphanumeric()||matches!(byte,b'.'|b'_'|b'-'))}

fn owner_only(path:&Path, directory:bool)->Result<()> {
    let meta=fs::symlink_metadata(path).with_context(||format!("inspect {}",path.display()))?;
    if meta.file_type().is_symlink() || (directory && !meta.is_dir()) || (!directory && !meta.is_file())
        || meta.uid()!=unsafe{libc::geteuid()} || meta.permissions().mode()&0o077!=0 { bail!("configured path is not owner-only: {}",path.display()); }
    Ok(())
}
fn env_path(name:&str,directory:bool)->Result<PathBuf>{
    let raw=std::env::var(name).with_context(||format!("required configuration {name} is missing"))?;
    let path=PathBuf::from(raw.trim());
    if raw.trim().is_empty()||!path.is_absolute(){bail!("{name} must be an absolute path");}
    if directory { owner_only(&path,true)?; } else { let parent=path.parent().context("state path has no parent")?; owner_only(parent,true)?; if !path.exists(){OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&path)?.sync_all()?;} owner_only(&path,false)?; }
    Ok(path)
}
fn zeroize_value(v:&mut Value){match v{Value::String(s)=>s.zeroize(),Value::Array(a)=>a.iter_mut().for_each(zeroize_value),Value::Object(o)=>o.values_mut().for_each(zeroize_value),_=>{}}}
fn scalar(mut v:Value)->Result<String>{
    let out=match &mut v{
        Value::String(s) if !s.is_empty()=>Ok(std::mem::take(s)),
        Value::Object(o) if o.len()==2&&o.get("type").and_then(Value::as_str).is_some()=>match o.get_mut("value"){Some(Value::String(s))if !s.is_empty()=>Ok(std::mem::take(s)),_=>bail!("vault item is not an exact scalar")},
        _=>bail!("vault item is not an exact scalar")}; zeroize_value(&mut v); out
}
fn authority_from_material(key_id:String,public:String,mut seed_text:String)->Result<Authority>{
    let mut seed=base64::engine::general_purpose::STANDARD.decode(seed_text.trim()).context("invalid signing seed encoding")?; seed_text.zeroize();
    let mut bytes:[u8;32]=seed.as_slice().try_into().map_err(|_|anyhow::anyhow!("signing seed must be 32 bytes"))?;
    let signing_key=SigningKey::from_bytes(&bytes); bytes.zeroize(); seed.zeroize();
    let expected=base64::engine::general_purpose::STANDARD.decode(public).context("invalid configured public key")?;
    if expected.as_slice()!=signing_key.verifying_key().as_bytes(){bail!("signing key does not match configured public key");}
    Ok(Authority{key_id,signing_key})
}
fn authority()->Result<Authority>{
    let vault=Vault::open(crate::vault_path())?;
    let key_id=scalar(vault.get_item("CANARY_KMS_KEY_ID").context("CANARY_KMS_KEY_ID unavailable")?)?;
    let public=scalar(vault.get_item("CANARY_PUBLIC_KEY_BASE64").context("CANARY_PUBLIC_KEY_BASE64 unavailable")?)?;
    let seed_text=scalar(vault.get_item("JEDEN_CANARY_RELEASE_SIGNING_KEY").context("JEDEN_CANARY_RELEASE_SIGNING_KEY unavailable")?)?;
    authority_from_material(key_id,public,seed_text)
}
fn read_regular(path:&Path,limit:u64)->Result<Vec<u8>>{
    let meta=fs::symlink_metadata(path)?; if meta.file_type().is_symlink()||!meta.is_file()||meta.uid()!=unsafe{libc::geteuid()}||meta.len()>limit{bail!("unsafe or oversized artifact file");}
    fs::read(path).with_context(||format!("read {}",path.display()))
}
fn open_archive(path:&Path,limit:u64)->Result<(File,u64)>{let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;let meta=file.metadata()?;if !meta.is_file()||meta.uid()!=unsafe{libc::geteuid()}||meta.len()>limit{bail!("unsafe or oversized release archive");}Ok((file,meta.len()))}
fn hash_file(file:&mut File)->Result<String>{file.seek(SeekFrom::Start(0))?;let mut digest=Sha256::new();let mut buf=[0u8;64*1024];loop{let n=file.read(&mut buf)?;if n==0{break;}digest.update(&buf[..n]);}file.seek(SeekFrom::Start(0))?;Ok(format!("{:x}",digest.finalize()))}
fn hash_path(path:&Path)->Result<String>{let (mut file,_)=open_archive(path,u64::MAX)?;hash_file(&mut file)}
fn canonical_line<T:for<'a>Deserialize<'a>>(bytes:&[u8],what:&str)->Result<T>{
    let raw=bytes.strip_suffix(b"\n").context(format!("{what} must end in one newline"))?;
    if raw.ends_with(b"\n"){bail!("{what} has extra trailing data");}
    let mut de=serde_json::Deserializer::from_slice(raw);let parsed=T::deserialize(&mut de).with_context(||format!("invalid {what}"))?;de.end()?;
    let value:Value=serde_json::from_slice(raw)?;if serde_json::to_vec(&value)?!=raw{bail!("{what} is not canonical JSON");}Ok(parsed)
}
fn safe_basename(value:&str)->bool{!value.is_empty()&&value.len()<=255&&Path::new(value).file_name().and_then(|v|v.to_str())==Some(value)&&!matches!(value,"."|"..")}
fn candidate(root:PathBuf,sha:&str,run_id:&str,run_attempt:u64,key_id:&str,_repo:&str)->Result<Candidate>{
    owner_only(&root,true)?;
    let name=root.file_name().and_then(|v|v.to_str()).context("artifact directory name invalid")?;
    if !name.contains(sha){bail!("artifact directory is not bound to source SHA");}
    let handoff_bytes=read_regular(&root.join("build-handoff.json"),1024*1024)?;
    let handoff:BuildHandoff=canonical_line(&handoff_bytes,"build handoff")?;
    let created=chrono::DateTime::parse_from_rfc3339(&handoff.created_at).context("handoff createdAt is not RFC3339")?;
    if handoff.schema!="jeden.release-build-handoff/v1"||handoff.repository!="wisent-ai/jeden"||handoff.head_sha!=sha
        ||created.offset().local_minus_utc()!=0||!handoff.created_at.ends_with('Z')||created>Utc::now()+Duration::minutes(5)||created<Utc::now()-Duration::days(2)
        ||handoff.build_run_id!=run_id||!decimal(&handoff.build_run_id)||handoff.build_run_attempt!=run_attempt
        ||!decimal(&handoff.contractual_ci_run_id)||handoff.contractual_ci_run_attempt==0
        ||!TARGETS.contains(&handoff.target_triple.as_str())||!coordinate(&handoff.version)||!coordinate(&handoff.target_triple)||semver::Version::parse(&handoff.version).is_err()||semver::Version::parse(&handoff.minimum_version).is_err()
        ||!safe_basename(&handoff.artifact.name)||!handoff.artifact.name.starts_with("jeden-")||!handoff.artifact.name.ends_with(".tar.gz")
        ||handoff.sbom.name!="sbom.spdx.json"||handoff.provenance.name!="provenance.intoto.json"
        ||![&handoff.artifact.sha256,&handoff.sbom.sha256,&handoff.provenance.sha256].into_iter().all(|v|lower_hex(v,64)){bail!("build handoff identity or shape denied");}
    let expected:BTreeSet<&str>=["build-handoff.json","release-gate-digests.json","sbom.spdx.json","provenance.intoto.json",handoff.artifact.name.as_str()].into_iter().collect();
    let mut actual=BTreeSet::new();for entry in fs::read_dir(&root)?{let entry=entry?;let n=entry.file_name().into_string().map_err(|_|anyhow::anyhow!("artifact filename is not UTF-8"))?;actual.insert(n);}
    if actual.iter().map(String::as_str).collect::<BTreeSet<_>>()!=expected{bail!("artifact directory does not match exact handoff allowlist");}
    let archive=root.join(&handoff.artifact.name);let (mut archive_file,archive_size)=open_archive(&archive,1024*1024*1024)?;let archive_digest=hash_file(&mut archive_file)?;let sbom=read_regular(&root.join("sbom.spdx.json"),64*1024*1024)?;let provenance=read_regular(&root.join("provenance.intoto.json"),64*1024*1024)?;
    if archive_digest!=handoff.artifact.sha256||archive_size!=handoff.artifact.size||hash(&sbom)!=handoff.sbom.sha256||hash(&provenance)!=handoff.provenance.sha256{bail!("handoff digest or size mismatch");}
    let gate_bytes=read_regular(&root.join("release-gate-digests.json"),1024*1024)?;let gate:GateRecord=canonical_line(&gate_bytes,"release gate record")?;
    if gate.schema!="jeden.release-gate-digests/v1"||gate.head_sha!=sha||gate.contractual_ci_run_id!=handoff.contractual_ci_run_id||gate.contractual_ci_run_attempt!=handoff.contractual_ci_run_attempt
        ||gate.reports.interface_equivalence.name!="interface-equivalence-report.json"||gate.reports.migration_matrix.name!="migration-matrix-report.json"
        ||!lower_hex(&gate.reports.interface_equivalence.sha256,64)||!lower_hex(&gate.reports.migration_matrix.sha256,64){bail!("release gates are not bound to contractual CI");}
    let release_root=format!("stado://releases/{PRODUCT}/{}/{}",handoff.version,handoff.target_triple);let now=created.with_timezone(&Utc);
    let schema_version="2".parse::<u64>()?;let expiry_days="7".parse::<i64>()?;
    let payload=json!({"schemaVersion":schema_version,"version":handoff.version,"channel":"canary","targetTriple":handoff.target_triple,"artifactUrl":format!("{release_root}/{}",handoff.artifact.name),"sha256":handoff.artifact.sha256,"size":handoff.artifact.size,"publishedAt":now.to_rfc3339_opts(SecondsFormat::Secs,true),"expiresAt":(now+Duration::days(expiry_days)).to_rfc3339_opts(SecondsFormat::Secs,true),"minimumVersion":handoff.minimum_version,"keyId":key_id,"provenanceRef":format!("{release_root}/provenance.intoto.json#sha256={}",handoff.provenance.sha256),"sbomRef":format!("{release_root}/sbom.spdx.json#sha256={}",handoff.sbom.sha256)});
    let payload_bytes=serde_json::to_vec(&payload)?;let mut pae=format!("DSSEv1 {} {} {} ",PAYLOAD_TYPE.len(),PAYLOAD_TYPE,payload_bytes.len()).into_bytes();pae.extend_from_slice(&payload_bytes);
    let archive_name=handoff.artifact.name;let mut files:BTreeMap<String,Vec<u8>>=BTreeMap::new();files.insert("sbom.spdx.json".into(),sbom);files.insert("provenance.intoto.json".into(),provenance);files.insert("manifest.payload.json".into(),payload_bytes);files.insert("manifest.pae".into(),pae);files.insert("release-gate-source.json".into(),gate_bytes);
    let mut digests:BTreeMap<String,String>=files.iter().map(|(k,v)|(k.clone(),hash(v))).collect();digests.insert(archive_name.clone(),archive_digest);Ok(Candidate{version:handoff.version,target:handoff.target_triple,archive_name,archive_file,files,digests})
}

fn encode_query(value:&str)->String{value.bytes().map(|byte|if byte.is_ascii_alphanumeric()||matches!(byte,b'-'|b'_'|b'.'|b'~'){(byte as char).to_string()}else{format!("%{byte:02X}")}).collect()}
fn remote_digest(reader:impl Read)->Result<(String,u64)>{
    let mut reader=reader;let mut digest=Sha256::new();let mut size=u64::default();let capacity="65536".parse::<usize>()?;let mut buffer=vec![u8::default();capacity];
    loop{let read=reader.read(&mut buffer)?;if read==usize::default(){break;}size=size.checked_add(read as u64).context("release object size overflow")?;digest.update(&buffer[..read]);}
    Ok((format!("{:x}",digest.finalize()),size))
}
impl StadoPublisher {
    fn configured()->Result<Self>{
        let raw=std::env::var("STADO_API_URL").context("STADO_API_URL is required")?;let base_url=raw.trim().trim_end_matches('/').to_string();
        let authority=base_url.strip_prefix("https://").context("STADO_API_URL must use HTTPS")?.split('/').next().unwrap_or_default();
        if authority.is_empty()||authority.contains('@')||base_url.contains('?')||base_url.contains('#')||base_url.bytes().any(|byte|byte.is_ascii_control()){bail!("STADO_API_URL must be an HTTPS API origin without credentials, query, or fragment");}
        let mut token=std::env::var("STADO_RELEASE_PUBLISHER_TOKEN").context("STADO_RELEASE_PUBLISHER_TOKEN is required")?;
        if token.trim().is_empty()||token.trim()!=token||token.bytes().any(|byte|byte.is_ascii_control()){bail!("STADO_RELEASE_PUBLISHER_TOKEN is empty or malformed");}
        for forbidden in ["STADO_API_TOKEN","GH_TOKEN","GITHUB_TOKEN"]{if std::env::var_os(forbidden).is_some(){bail!("{forbidden} is forbidden for release-publish; use only the dedicated Stado publisher bearer");}}
        let authorization=format!("Bearer {token}");token.zeroize();let agent=ureq::AgentBuilder::new().redirects(u32::default()).build();Ok(Self{base_url,authorization,agent})
    }
    fn object_url(&self,uri:&str)->String{format!("{}/api/object?uri={}&if_absent=true",self.base_url,encode_query(uri))}
    fn release_url(&self,uri:&str)->String{format!("{}/api/release/object?uri={}",self.base_url,encode_query(uri))}
    fn existing_matches(&self,uri:&str,digest:&str,size:u64)->Result<bool>{
        let response=self.agent.get(&self.release_url(uri)).set("Accept","application/octet-stream").set("User-Agent","skarbiec-release-publisher").call().map_err(|_|anyhow::anyhow!("Stado release conflict could not be verified"))?;
        let (remote_hash,remote_size)=remote_digest(response.into_reader())?;Ok(remote_hash==digest&&remote_size==size)
    }
    fn put_file(&self,uri:&str,path:&Path)->Result<bool>{
        let mut file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;let metadata=file.metadata()?;if !metadata.is_file(){bail!("staged release object is not a regular file");}
        let digest=hash_file(&mut file)?;let size=metadata.len();let content_type=if path.file_name().and_then(|name|name.to_str())==Some("SHA256SUMS"){ "text/plain" }else if path.extension().and_then(|value|value.to_str())==Some("json"){ "application/json" }else{ "application/octet-stream" };
        let conflict="409".parse::<u16>()?;let precondition="412".parse::<u16>()?;
        match self.agent.put(&self.object_url(uri)).set("Authorization",&self.authorization).set("Content-Type",content_type).set("User-Agent","skarbiec-release-publisher").send(file){Ok(_)=>Ok(true),Err(ureq::Error::Status(code,_))if code==conflict||code==precondition=>{if self.existing_matches(uri,&digest,size)?{Ok(false)}else{bail!("immutable Stado release object conflicts with different bytes: {uri}")}},Err(_)=>bail!("Stado create-only release PUT failed: {uri}")}
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFile { seq:u64, at:String, op:String, subject_hash:String, prev_hash:String, event_hash:String, manifest_sha256:String, release_root:String }
fn open_state(path:&Path)->Result<Connection>{
    let conn=Connection::open(path)?; fs::set_permissions(path,fs::Permissions::from_mode(0o600))?;
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS publications(repo TEXT NOT NULL,run_id TEXT NOT NULL,source_sha TEXT NOT NULL,target TEXT NOT NULL,release_root TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,completed_at TEXT NOT NULL,PRIMARY KEY(repo,run_id,source_sha,target)); CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY,at TEXT NOT NULL,op TEXT NOT NULL,subject_hash TEXT NOT NULL,prev_hash TEXT NOT NULL,event_hash TEXT NOT NULL);")?;
    let current_schema:bool=conn.query_row("SELECT EXISTS(SELECT name FROM pragma_table_info('publications') WHERE name='release_root')",[],|row|row.get(usize::default()))?;if !current_schema{bail!("legacy GitHub publication state is incompatible; configure fresh Stado publish state and audit paths");}Ok(conn)
}
fn verify_audit(conn:&Connection,dir:&Path)->Result<()> {
    let count:u64=conn.query_row("SELECT count(*) FROM audit",[],|r|r.get(0))?;
    let publications:u64=conn.query_row("SELECT count(*) FROM publications",[],|r|r.get(0))?;
    if publications!=count{bail!("release publication/audit state mismatch");}
    let files=fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>,_>>()?;
    if files.len() as u64!=count{bail!("release audit WORM/state mismatch");}
    let mut prev=String::new();
    for seq in 1..=count {
        let path=dir.join(format!("{seq:020}.json"));let meta=fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink()||!meta.is_file()||meta.permissions().mode()&0o222!=0{bail!("release audit file is mutable or invalid");}
        let record:AuditFile=canonical_line(&fs::read(&path)?,"release audit record")?;
        let expected=hash(format!("{}\0{}\0{}\0{}\0{}\0{}\0{}",record.seq,record.at,record.op,record.subject_hash,record.prev_hash,record.manifest_sha256,record.release_root).as_bytes());
        let stored:Option<(String,String)>=conn.query_row("SELECT prev_hash,event_hash FROM audit WHERE seq=?1",[seq],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if record.seq!=seq||record.op!="release-publish"||record.prev_hash!=prev||record.event_hash!=expected||stored!=Some((record.prev_hash.clone(),record.event_hash.clone())){bail!("release audit hash chain invalid");}
        prev=record.event_hash;
    }
    Ok(())
}
fn record(conn:&mut Connection,dir:&Path,subject:&str,manifest:&str,release_root:&str,repo:&str,run_id:&str,sha:&str,target:&str)->Result<()> {
    let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?;let (seq,prev):(u64,String)=tx.query_row("SELECT COALESCE(MAX(seq),0)+1,COALESCE((SELECT event_hash FROM audit ORDER BY seq DESC LIMIT 1),'') FROM audit",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    let at=Utc::now().to_rfc3339_opts(SecondsFormat::Secs,true);let subject_hash=hash(subject.as_bytes());let event_hash=hash(format!("{seq}\0{at}\0release-publish\0{subject_hash}\0{prev}\0{manifest}\0{release_root}").as_bytes());
    let body=serde_json::to_vec(&json!({"seq":seq,"at":at,"op":"release-publish","subject_hash":subject_hash,"prev_hash":prev,"event_hash":event_hash,"manifest_sha256":manifest,"release_root":release_root}))?;
    let path=dir.join(format!("{seq:020}.json"));let mut f=OpenOptions::new().write(true).create_new(true).mode(0o400).custom_flags(libc::O_NOFOLLOW).open(path)?;f.write_all(&body)?;f.write_all(b"\n")?;f.sync_all()?;OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW).open(dir)?.sync_all()?;
    tx.execute("INSERT INTO publications(repo,run_id,source_sha,target,release_root,manifest_sha256,completed_at)VALUES(?1,?2,?3,?4,?5,?6,?7)",params![repo,run_id,sha,target,release_root,manifest,at])?;
    tx.execute("INSERT INTO audit(seq,at,op,subject_hash,prev_hash,event_hash)VALUES(?1,?2,'release-publish',?3,?4,?5)",params![seq,at,subject_hash,prev,event_hash])?;tx.commit()?;Ok(())
}
fn octal(value:&str)->Result<u32>{Ok(u32::from_str_radix(value,"8".parse()?)?)}
fn write_staging(parent:&Path,c:&Candidate,envelope:&[u8],gates:&[u8])->Result<PathBuf>{
    let dir=parent.join(format!(".release-publish-{}",hash(format!("{}:{}",c.target,Utc::now().timestamp_nanos_opt().unwrap_or_default()).as_bytes())));fs::create_dir(&dir)?;fs::set_permissions(&dir,fs::Permissions::from_mode(octal("700")?))?;
    let archive_path=dir.join(&c.archive_name);let mut source=c.archive_file.try_clone()?;source.seek(SeekFrom::Start(usize::default() as u64))?;let mut archive=OpenOptions::new().write(true).create_new(true).mode(octal("600")?).custom_flags(libc::O_NOFOLLOW).open(&archive_path)?;std::io::copy(&mut source,&mut archive)?;archive.sync_all()?;if hash_path(&archive_path)?!=c.digests[&c.archive_name]{bail!("release archive changed after validation");}
    for (name,data) in c.files.iter().filter(|(name,_)|*name!="manifest.payload.json"&&*name!="manifest.pae"&&*name!="release-gate-source.json"){let path=dir.join(name);let mut file=OpenOptions::new().write(true).create_new(true).mode(octal("600")?).open(path)?;file.write_all(data)?;file.sync_all()?;}
    for (name,data) in [("manifest.dsse.json",envelope),("release-gate-digests.json",gates)]{let mut file=OpenOptions::new().write(true).create_new(true).mode(octal("600")?).open(dir.join(name))?;file.write_all(data)?;file.sync_all()?;}
    let mut staged=BTreeMap::new();for entry in fs::read_dir(&dir)?{let entry=entry?;let name=entry.file_name().into_string().map_err(|_|anyhow::anyhow!("staged name invalid"))?;staged.insert(name,hash_path(&entry.path())?);}let sums=staged.into_iter().map(|(name,digest)|format!("{digest}  {name}\n")).collect::<String>();
    let mut checksum=OpenOptions::new().write(true).create_new(true).mode(octal("600")?).open(dir.join("SHA256SUMS"))?;checksum.write_all(sums.as_bytes())?;checksum.sync_all()?;Ok(dir)
}
fn signed_envelope(authority:&Authority,payload:&[u8],pae:&[u8])->Result<Vec<u8>>{
    let signature=authority.signing_key.sign(pae);
    let mut envelope=serde_json::to_vec(&json!({"payloadType":PAYLOAD_TYPE,"payload":base64::engine::general_purpose::STANDARD.encode(payload),"signatures":[{"keyid":authority.key_id,"sig":base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())}]}))?;
    envelope.push(b'\n');
    Ok(envelope)
}

fn publish_one(publisher:&StadoPublisher,conn:&mut Connection,audit_dir:&Path,state_parent:&Path,authority:&Authority,repo:&str,run_id:&str,sha:&str,c:Candidate)->Result<Value>{
    let release_root=format!("stado://releases/{PRODUCT}/{}/{}",c.version,c.target);let subject=format!("{repo}:{run_id}:{sha}:{}:{}",c.version,c.target);
    let payload=c.files.get("manifest.payload.json").context("validated manifest payload missing")?;let pae=c.files.get("manifest.pae").context("validated manifest PAE missing")?;
    let envelope=signed_envelope(authority,payload,pae)?;let manifest_digest=hash(&envelope);
    let source:Value=serde_json::from_slice(c.files.get("release-gate-source.json").context("validated gate source missing")?)?;let schema_version="1".parse::<u64>()?;
    let gates=serde_json::to_vec(&json!({"schemaVersion":schema_version,"sourceSha":sha,"version":c.version,"targetTriple":c.target,"artifactSha256":c.digests[&c.archive_name],"manifestPayloadSha256":hash(payload),"manifestEnvelopeSha256":manifest_digest,"sbomSha256":c.digests["sbom.spdx.json"],"provenanceSha256":c.digests["provenance.intoto.json"],"workflowRun":run_id,"sourceGateRecordSha256":hash(c.files["release-gate-source.json"].as_slice()),"sourceGateSchema":source.get("schema").cloned().unwrap_or(Value::Null)}))?;
    let stage=write_staging(state_parent,&c,&envelope,&gates)?;
    let existing:Option<String>=conn.query_row("SELECT manifest_sha256 FROM publications WHERE repo=?1 AND run_id=?2 AND source_sha=?3 AND target=?4",params![repo,run_id,sha,c.target],|row|row.get(usize::default())).optional()?;
    if existing.as_deref().is_some_and(|stored|stored!=manifest_digest){bail!("recorded publication differs from signed release manifest");}
    let mut objects=BTreeMap::new();for entry in fs::read_dir(&stage)?{let entry=entry?;let name=entry.file_name().into_string().map_err(|_|anyhow::anyhow!("staged name invalid"))?;objects.insert(name,entry.path());}
    let checksum=objects.remove("SHA256SUMS").context("staged SHA256SUMS missing")?;let mut created=false;
    for (name,path) in objects{created|=publisher.put_file(&format!("{release_root}/{name}"),&path)?;}
    created|=publisher.put_file(&format!("{release_root}/SHA256SUMS"),&checksum)?;fs::remove_dir_all(&stage)?;
    if existing.is_none(){record(conn,audit_dir,&subject,&manifest_digest,&release_root,repo,run_id,sha,&c.target)?;}
    Ok(json!({"target":c.target,"version":c.version,"release_root":release_root,"status":if created{"published"}else{"already-published"},"manifest_sha256":manifest_digest}))
}

pub fn command(flags:&HashMap<String,String>,positionals:&[String])->Result<Value>{
    if !positionals.is_empty()||flags.keys().any(|key|!["artifact-dir","repository","run-id","run-attempt","sha","product"].contains(&key.as_str())){bail!("usage: release-publish --artifact-dir DIR --repository Wisent-AI/jeden --run-id N --run-attempt N --sha HEX --product jeden");}
    let repo=flags.get("repository").map(String::as_str).context("--repository required")?;let run_id=flags.get("run-id").map(String::as_str).context("--run-id required")?;let run_attempt=flags.get("run-attempt").context("--run-attempt required")?.parse::<u64>().context("--run-attempt invalid")?;let sha=flags.get("sha").map(String::as_str).context("--sha required")?;
    let sha_length="40".parse::<usize>()?;if repo!=REPOSITORY||flags.get("product").map(String::as_str)!=Some(PRODUCT)||!decimal(run_id)||run_attempt==u64::default()||!lower_hex(sha,sha_length){bail!("release identity denied");}
    let root=PathBuf::from(flags.get("artifact-dir").context("--artifact-dir required")?);if !root.is_absolute(){bail!("artifact directory must be absolute");}owner_only(&root,true)?;
    let state=env_path("SKARBIEC_RELEASE_PUBLISH_STATE",false)?;let audit_dir=env_path("SKARBIEC_RELEASE_AUDIT_DIR",true)?;let mut conn=open_state(&state)?;verify_audit(&conn,&audit_dir)?;
    let authority=authority()?;let publisher=StadoPublisher::configured()?;let mut candidates=Vec::new();for entry in fs::read_dir(&root)?{let entry=entry?;candidates.push(candidate(entry.path(),sha,run_id,run_attempt,&authority.key_id,repo)?);}if candidates.is_empty(){bail!("no release artifacts found");}
    candidates.sort_by(|left,right|left.target.cmp(&right.target));let mut targets=BTreeSet::new();let mut versions=BTreeSet::new();if candidates.iter().any(|candidate|!targets.insert(candidate.target.clone())||!versions.insert(candidate.version.clone()))||versions.len()!="1".parse::<usize>()?{bail!("release handoff must contain one version and unique target artifacts");}
    let state_parent=state.parent().context("release state path has no parent")?;let mut results=Vec::new();for candidate in candidates{results.push(publish_one(&publisher,&mut conn,&audit_dir,state_parent,&authority,repo,run_id,sha,candidate)?);}Ok(json!({"status":"complete","published":results}))
}

