# Future Improvements — WAF Environment

Known issues deliberately left alone, not in scope for any current sprint.

## Use `BLOCKING_PARANOIA` instead of `PARANOIA`

*Found during the Step 2 code review, 2026-11-06. Left as is because of the time remaining before
final deliverables.*

`docker-compose.yml` line 15 sets `PARANOIA: "1"`. The image's config
(`/docker-entrypoint.d/configure-rules.v4.conf`) marks that name as "Superceded by
`BLOCKING_PARANOIA`", and the image also sets `BLOCKING_PARANOIA=1` itself.

Both are 1, and the running `crs-setup.conf` has `tx.blocking_paranoia_level=1`, so nothing is wrong
at the current level. However, changing only `PARANOIA` may not take effect (not tested). Check this
before running any experiment at a higher paranoia level by confirming the value in `crs-setup.conf`
inside the container.

## Limit the published WAF port to loopback

*Found during the Step 2 code review, 2026-11-06. Left as is for the same reason.*

`"8080:8080"` publishes the port on all network interfaces. `"127.0.0.1:8080:8080"` would limit it
to the local host. See "What is NOT protected" in `SECURITY.md`.
