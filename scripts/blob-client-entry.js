// Bundled to public/vendor/blob-client.js (npm run build:client). Exposes window.EcidBlob.upload.
import { upload } from '@vercel/blob/client';
window.EcidBlob = { upload };
