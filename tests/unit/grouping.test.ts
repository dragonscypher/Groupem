import { describe, expect, it } from 'vitest';
import { domainGroup, purity } from '../../shared/src/grouping';

describe('grouping', () => {
    it('groups by eTLD+1', () => {
        const tabs = [
            { id: '1', url: 'https://sub.example.com/a' },
            { id: '2', url: 'https://www.example.com/b' },
            { id: '3', url: 'https://other.org/x' }
        ];
        const groups = domainGroup(tabs as any);
        const map: Record<string, string[]> = {};
        for (const g of groups) map[g.label] = g.tabIds;
        expect(map['example.com'].length).toBe(2);
        expect(map['other.org'].length).toBe(1);
    });

    it('purity perfect when predicted == expected', () => {
        const expected = { 'example.com': ['1', '2'], 'other.org': ['3'] };
        const predicted = [{ label: 'example.com', tabIds: ['1', '2'] }, { label: 'other.org', tabIds: ['3'] }];
        expect(purity(expected, predicted)).toBe(1);
    });
});
