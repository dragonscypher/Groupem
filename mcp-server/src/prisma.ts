import { PrismaClient } from '@prisma/client';

// Singleton Prisma client to reuse across server and tests
export const prisma = new PrismaClient();
export default prisma;
