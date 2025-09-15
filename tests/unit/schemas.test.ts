import { SessionSchema } from '@groupem/shared/dist/models';
import { describe, expect, it } from 'vitest';

describe('schemas', () => {
    it('valid session schema', () => {
        const session = { id: 's1', createdAt: new Date().toISOString(), device: 'dev', groups: [] };
        expect(() => SessionSchema.parse(session)).not.toThrow();
    });
});
