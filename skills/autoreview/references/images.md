# Image review

Branch mode with Codex supports **added, single-frame PNG, JPEG and WebP** files.
Install Pillow in the Python environment running the helper (`python -m pip install Pillow`).
Use a vision-capable Codex model and a CLI supporting `codex exec --image`.
No new bypass flag is required. Full decoding rejects corrupt and animated files.
Images must have at most 16,777,216 pixels and no dimension above 16,384 pixels;
decoder bomb warnings fail closed before pixel loading. Added image paths are
limited to 20 MiB of encoded bytes each and 100 MiB total, checked against Git
object sizes before capture. Exceeding a limit fails the entire review.

The helper captures exact bytes from the pinned HEAD, stages only those images
in its isolated workspace, and attaches them through Codex's native image input.
Every pass receives the path, media type, byte count and SHA-256 manifest alongside
the image attachments and text diff. Image findings use the original path and line 1.
Text-only review does not require Pillow.

Binary deletions, including images, are reviewed as deletion metadata in every
mode without image attachments or Pillow. Other binaries, modified images,
local/commit image additions or modifications, and image review with other engines
remain unsupported and fail closed. Missing Pillow or provider
image limits fail the review rather than silently dropping assets. Sensitive-path,
source-mutation, authentication and sandbox controls remain enabled.

For partial clones, materialize required Git objects **before** review. The isolated
Git reader intentionally disables lazy network fetching; do not weaken that boundary.
