# Release Process

The component is a Go module in the `honeycombauthextension/` subdirectory, so release tags
must carry the subdirectory prefix (a Go requirement for subdirectory modules): plain `vX.Y.Z`
tags will not resolve as module versions.

1. Update `CHANGELOG.md` with the changes since the last release:

    ```sh
    git log honeycombauthextension/<last-version>..HEAD --pretty='- %s'
    ```

2. Commit, push, and open a release preparation pull request for review.

3. Once merged, fetch the updated `main` branch and tag it with the new version:

    ```sh
    make release VERSION=v1.2.3
    ```

    (equivalent to `git tag -a honeycombauthextension/v1.2.3 -m ... && git push origin honeycombauthextension/v1.2.3`)

4. Pushing the tag triggers the release workflow, which runs the test suite and publishes a
   GitHub release with generated notes and module checksums.

5. To pick the new version up in `honeycombio/honeycomb-collector-distro`, update the
   `honeycombauthextension` entry in its `builder-config.yaml`.
