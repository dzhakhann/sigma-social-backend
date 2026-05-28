import { Logger } from '../utils/logger';

const logger = new Logger('Supabase');

let supabase: any = null;

export const initializeSupabase = () => {
  try {
    logger.info('✅ Supabase mock initialized');
    return supabase;
  } catch (error) {
    logger.error('Failed to initialize Supabase:', error);
    throw error;
  }
};

export const getSupabase = () => {
  if (!supabase) {
    logger.warn('Supabase not initialized, returning null');
  }
  return supabase;
};

export default supabase;