use std::sync::Barrier;
use std::thread;

use super::support::assert_success;
use super::{answer, fixture, route, LOGIN_ITEM};

#[test]
fn concurrent_consumers_preserve_every_declared_route() {
    let fixture = fixture();
    let writers = 8;
    let barrier = Barrier::new(writers);
    let completed = thread::scope(|scope| {
        let workers: Vec<_> = (0..writers)
            .map(|index| {
                let fixture = &fixture;
                let barrier = &barrier;
                scope.spawn(move || {
                    let resource =
                        format!("origin:https://consumer-{index}.example.invalid/password");
                    barrier.wait();
                    let output = fixture.run(&[
                        "route",
                        "declare",
                        "--resource",
                        &resource,
                        "--item",
                        LOGIN_ITEM,
                        "--field",
                        "password",
                        "--reason",
                        "A consumer declares its sign-in origin into the shared broker.",
                    ]);
                    (resource, output)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("route writer completed"))
            .collect::<Vec<_>>()
    });

    for (resource, output) in completed {
        assert_success(&format!("declare {resource}"), &output);
        let persisted = answer(&fixture, &["route", "resolve", &resource]);
        let resolved = route(&persisted, &resource, "password");
        assert_eq!(resolved["item"], LOGIN_ITEM);
        assert_eq!(resolved["field_present"], true);
    }
}
