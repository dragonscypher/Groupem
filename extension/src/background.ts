import browser from 'webextension-polyfill';
// Fallback declaration for chrome namespace in MV3 build if types not included
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const chrome: any;

browser.runtime.onInstalled.addListener(() => {
    console.log('Groupem background ready');
    try {
        chrome.management.getSelf((self: any) => {
            if (self && self.id) {
                chrome.storage.local.set({ __GROUPEM_EXT_ID: self.id });
            }
        });
    } catch { }
});

browser.tabs.onCreated.addListener((tab: any) => {
    console.log('Tab created', tab?.id);
});

browser.runtime.onMessage.addListener((msg: any) => {
    if (msg?.type === 'groupem-activate') {
        console.log('Activator ping received');
        try {
            chrome.management.getSelf((self: any) => {
                if (self && self.id) {
                    chrome.storage.local.set({ __GROUPEM_EXT_ID: self.id });
                }
            });
        } catch { }
    }
});
