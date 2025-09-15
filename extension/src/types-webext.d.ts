declare module 'webextension-polyfill' {
    const browser: any;
    export default browser;
}

// Minimal chrome namespace declarations used in tests/background
// (Avoid pulling full @types/chrome to keep footprint small.)
declare const chrome: any;
