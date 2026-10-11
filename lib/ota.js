/** itms-services OTA manifest helpers. iOS requires the manifest and IPA over valid HTTPS. */
const { buildXmlPlist } = require('./plist-lite');

function buildManifest({ ipaUrl, bundleId, version, title }) {
  return buildXmlPlist({
    items: [
      {
        assets: [{ kind: 'software-package', url: ipaUrl }],
        metadata: {
          'bundle-identifier': bundleId,
          'bundle-version': version || '1.0',
          kind: 'software',
          title: title || bundleId,
        },
      },
    ],
  });
}

function installLink(manifestUrl) {
  return 'itms-services://?action=download-manifest&url=' + encodeURIComponent(manifestUrl);
}

module.exports = { buildManifest, installLink };
