# Web Hello World

Start the challenge instance and send an HTTP `GET` request to `/` to see the greeting (`Hello, Ret2Shell World!`), then request `/flag` (or `/flag.txt`) to read the dynamic `FLAG` environment variable injected into the container.

```bash
curl http://<host>:<port>/flag
```

Submit the returned `flag{...}` string to complete the challenge.
