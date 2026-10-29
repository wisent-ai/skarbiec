// What on this machine reads one item by its id each time it runs: the AWS
// profiles whose credential_process is this vault's `helper answer aws` for
// it, and the kubeconfig users whose exec is its `helper answer kube` for it.
// delete names them, since each fails once the item is in the trash, and
// exposure names them, since each hands the value to whatever runs under
// that profile or user. A configuration that cannot be read leaves its list
// empty and says why beside it, so an empty list never hides a failure.

use serde_json::{json, Value};

/// The profiles and users reading `id`, with aws_error and kube_error naming
/// why a list could not be read, null when it was.
pub(crate) fn naming(id: &str) -> Value {
    let (aws, aws_error) = match crate::runtime::awscred::profiles() {
        Ok((_, found)) => (found.iter().filter(|profile| profile.item == id).map(|profile| profile.name.clone()).collect(), None),
        Err(error) => (Vec::new(), Some(format!("{error:#}"))),
    };
    let listed = crate::runtime::kubecred::kubectl_on_path().and_then(|on_path| {
        if on_path {
            crate::runtime::kubecred::users()
        } else {
            Ok(Vec::new())
        }
    });
    let (kube, kube_error) = match listed {
        Ok(found) => (found.iter().filter(|user| user.item == id).map(|user| user.name.clone()).collect(), None),
        Err(error) => (Vec::new(), Some(format!("{error:#}"))),
    };
    let aws: Vec<String> = aws;
    let kube: Vec<String> = kube;
    json!({"aws_profiles": aws, "aws_error": aws_error, "kubeconfig_users": kube, "kube_error": kube_error})
}
