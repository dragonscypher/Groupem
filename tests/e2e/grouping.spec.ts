import { expect, test } from '@playwright/test';
// Using shared grouping logic indirectly: replicate domain grouping similarly to extension logic.

function syntheticUrls(): { expected: Record<string, string[]>; urls: string[] } {
    const domains: Record<string, string> = {
        'news.siteA.com': 'siteA.com',
        'blog.siteA.com': 'siteA.com',
        'shop.siteB.com': 'siteB.com',
        'media.siteB.com': 'siteB.com',
        'dev.siteC.io': 'siteC.io',
        'docs.siteC.io': 'siteC.io',
        'api.siteD.net': 'siteD.net',
        'www.siteD.net': 'siteD.net'
    };
    const urls: string[] = [];
    const expected: Record<string, string[]> = {};
    let idCounter = 1;
    for (const host of Object.keys(domains)) {
        for (let i = 0; i < 3; i++) { // 3 pages per subdomain variant
            const id = `t${idCounter++}`;
            const url = `https://${host}/path/${i}`;
            urls.push(url);
            const group = domains[host as keyof typeof domains];
            (expected[group] ||= []).push(id);
        }
    }
    return { expected, urls };
}

function groupLikeExtension(urls: string[]): { label: string; tabIds: string[] }[] {
    const buckets: Record<string, string[]> = {};
    let idCounter = 1;
    for (const u of urls) {
        try {
            const host = new URL(u).hostname.split('.').slice(-2).join('.');
            (buckets[host] ||= []).push(`t${idCounter}`);
        } catch {
            (buckets['other'] ||= []).push(`t${idCounter}`);
        }
        idCounter++;
    }
    return Object.entries(buckets).map(([label, tabIds]) => ({ label, tabIds }));
}

function purity(expected: Record<string, string[]>, predicted: { label: string; tabIds: string[] }[]): number {
    const predictedMap: Record<string, Set<string>> = {};
    for (const g of predicted) predictedMap[g.label] = new Set(g.tabIds);
    let total = 0; let correct = 0;
    for (const tabs of Object.values(expected)) {
        total += tabs.length;
        let maxOverlap = 0;
        for (const p of Object.values(predictedMap)) {
            let overlap = 0;
            for (const id of tabs) if (p.has(id)) overlap++;
            if (overlap > maxOverlap) maxOverlap = overlap;
        }
        correct += maxOverlap;
    }
    return total ? correct / total : 1;
}

test('synthetic grouping purity >= 0.85', async () => {
    const { expected, urls } = syntheticUrls();
    const predicted = groupLikeExtension(urls);
    const p = purity(expected, predicted);
    expect(p).toBeGreaterThanOrEqual(0.85);
});
