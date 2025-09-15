import { z } from 'zod';

export const TabSchema = z.object({
    id: z.string(),
    url: z.string().url(),
    title: z.string(),
    favicon: z.string().optional(),
    windowId: z.number(),
    lastActiveAt: z.string(),
    pinned: z.boolean().optional()
});
export type Tab = z.infer<typeof TabSchema>;

export const TabGroupSchema = z.object({
    id: z.string(),
    label: z.string(),
    category: z.string(),
    tabIds: z.array(z.string()),
    embeddingId: z.string().optional(),
    score: z.number().optional()
});
export type TabGroup = z.infer<typeof TabGroupSchema>;

export const SessionSchema = z.object({
    id: z.string(),
    createdAt: z.string(),
    groups: z.array(TabGroupSchema),
    device: z.string()
});
export type Session = z.infer<typeof SessionSchema>;

export const FileMetaSchema = z.object({
    id: z.string(),
    name: z.string(),
    mime: z.string(),
    size: z.number(),
    tags: z.array(z.string()),
    createdAt: z.string()
});
export type FileMeta = z.infer<typeof FileMetaSchema>;

export const EmbeddingSchema = z.object({
    id: z.string(),
    objectId: z.string(),
    kind: z.string(),
    vector: z.array(z.number()),
    dim: z.number()
});
export type Embedding = z.infer<typeof EmbeddingSchema>;

export const StoredSessionSchema = SessionSchema.extend({
    userId: z.string()
});

export const AuthUserSchema = z.object({
    id: z.string(),
    email: z.string().email(),
    passwordHash: z.string(),
    totpSecret: z.string().nullable(),
    webAuthnCredentialId: z.string().nullable(),
    createdAt: z.string()
});
export type AuthUser = z.infer<typeof AuthUserSchema>;

export const StorageRecordSchema = z.object({
    id: z.string(),
    userId: z.string(),
    key: z.string(),
    valueCipher: z.string(),
    tags: z.array(z.string()),
    createdAt: z.string()
});

export const EmbeddingObjectSchema = z.object({
    id: z.string(),
    text: z.string(),
    kind: z.string()
});

export const EmbeddingQueryResultSchema = z.object({
    objectId: z.string(),
    score: z.number()
});

export const SessionListResponseSchema = z.object({
    items: z.array(SessionSchema),
    nextCursor: z.string().optional()
});

export const SaveGroupsInputSchema = z.object({ session: SessionSchema });
export const SaveGroupsOutputSchema = z.object({ id: z.string() });

export const LoadGroupsInputSchema = z.object({ id: z.string() });
export const LoadGroupsOutputSchema = SessionSchema;

export const ListGroupsInputSchema = z.object({ limit: z.number().optional(), cursor: z.string().optional() });
export const ListGroupsOutputSchema = SessionListResponseSchema;

export const MergeGroupsInputSchema = z.object({ baseId: z.string(), incoming: SessionSchema });
export const MergeGroupsOutputSchema = z.object({ id: z.string() });

export const StoragePutInputSchema = z.object({ key: z.string(), value: z.any(), tags: z.array(z.string()).optional() });
export const StoragePutOutputSchema = z.object({ ok: z.boolean() });

export const StorageGetInputSchema = z.object({ key: z.string() });
export const StorageGetOutputSchema = z.object({ value: z.any().optional() });

export const StorageSearchInputSchema = z.object({ query: z.string() });
export const StorageSearchOutputSchema = z.object({ keys: z.array(z.string()) });

export const EmbeddingsIndexInputSchema = z.object({ objects: z.array(EmbeddingObjectSchema) });
export const EmbeddingsIndexOutputSchema = z.object({ ok: z.boolean() });

export const EmbeddingsQueryInputSchema = z.object({ text: z.string(), topK: z.number() });
export const EmbeddingsQueryOutputSchema = z.array(EmbeddingQueryResultSchema);

export const AuthEnrollTotpOutputSchema = z.object({ secret: z.string(), otpauthUrl: z.string() });
export const AuthVerifyTotpInputSchema = z.object({ code: z.string() });
export const AuthVerifyTotpOutputSchema = z.object({ ok: z.boolean() });

export type SaveGroupsInput = z.infer<typeof SaveGroupsInputSchema>;
export type SaveGroupsOutput = z.infer<typeof SaveGroupsOutputSchema>;
export type LoadGroupsInput = z.infer<typeof LoadGroupsInputSchema>;
export type ListGroupsInput = z.infer<typeof ListGroupsInputSchema>;
export type MergeGroupsInput = z.infer<typeof MergeGroupsInputSchema>;
export type StoragePutInput = z.infer<typeof StoragePutInputSchema>;
export type StorageGetInput = z.infer<typeof StorageGetInputSchema>;
export type StorageSearchInput = z.infer<typeof StorageSearchInputSchema>;
export type EmbeddingsIndexInput = z.infer<typeof EmbeddingsIndexInputSchema>;
export type EmbeddingsQueryInput = z.infer<typeof EmbeddingsQueryInputSchema>;
export type AuthVerifyTotpInput = z.infer<typeof AuthVerifyTotpInputSchema>;
