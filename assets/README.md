# Assets for Nightmare Watch

This folder contains master vector artwork and UI SVGs for the Nightmare Watch project. These are designed as editable SVGs so you can export PNGs at the sizes you need.

Files added on branch `assets/add-images`:

- assets/logo.svg — master wordmark + icon (SVG). Use this as the source for exported icons and banners.
- assets/icon-foreground.svg — icon (eye+shield) on transparent background (SVG).
- assets/icon-background.svg — simple dark rounded background (SVG) (used together with foreground for adaptive icons).
- assets/banner-1200x360.svg — README / hero banner (SVG).
- assets/social-1200x630.svg — Open Graph / social preview (SVG).
- assets/screenshot-dashboard-1365x768.svg — in-app dashboard mockup (SVG).
- assets/ui-icons/scan.svg, shield.svg, vpn.svg — small UI icons (SVG).

Recommended PNG export sizes (examples):
- App icon: 1024x1024 (icon-1024.png)
- Adaptive/icon foreground: 512x512 (icon-foreground.svg export)
- Favicon: 32x32 (favicon-32.png) and .ico (favicon.ico)
- README banner: 1200x360
- Open Graph/social image: 1200x630
- In-app screenshot placeholder: 1365x768

Export commands (Inkscape examples):

- Export 1024×1024 PNG from SVG (Inkscape 1.0+):
  inkscape assets/icon-foreground.svg --export-filename=assets/icon-1024.png --export-width=1024 --export-height=1024

- Export banner 1200×360:
  inkscape assets/banner-1200x360.svg --export-filename=assets/banner-1200x360.png --export-width=1200 --export-height=360

- Export social 1200×630:
  inkscape assets/social-1200x630.svg --export-filename=assets/social-1200x630.png --export-width=1200 --export-height=630

- Create favicon from 32×32 PNG (ImageMagick):
  convert assets/favicon-32.png assets/favicon.ico

If you want, I can export and commit the PNGs and the favicon for you (I can generate raster PNGs from these SVGs and add them to the branch). Reply `export pngs` and I'll add the PNG exports and the favicon.ico to the branch.
