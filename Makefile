# The commands this repository is checked and built with.
#
# They live in a checked-in file rather than in whatever a person types, so the
# verdict here, the one a Stado recipe reaches on every commit and the one a
# release candidate is measured against come from the same words.

.PHONY: check build release

# Does the working copy compile, and does every journey keep a program's
# standard error out of the answer it compares? The cheap question, and the
# one to ask after an edit: a build is rationed, a check is not.
check:
	cargo check --locked
	bash tools/check-journey-streams.sh tests

build:
	cargo build --locked

# What a delivery installs.
release:
	cargo build --locked --release
