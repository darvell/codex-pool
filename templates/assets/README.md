# Favicon artwork

`watering-can.png` is the unchanged original artwork. `favicon.ico` contains
transparent 16, 32, and 48 pixel versions, with empty margins trimmed and a small
amount of padding added without changing the aspect ratio.

To regenerate from the repository root, use Python with Pillow 12.3.0 installed:

```sh
python3 scripts/generate_favicon.py
```

The generated ICO is committed and embedded in the Go binary. Pillow is only
needed when regenerating it, not for application builds or deployment.
