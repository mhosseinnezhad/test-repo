package com.modernisc.security.keycloak.iam.util;

import java.util.concurrent.ConcurrentHashMap;

public class MyCache {
    private static ConcurrentHashMap<String, CachedItem> cachedItems = new ConcurrentHashMap<>();

    public static Object extract(String cacheKey, ValueSupplier valueSupplier) throws Exception {
        Object value = MyCache.get(cacheKey);
        if (value != null) {
            return value;
        }

        value = valueSupplier.get();

        MyCache.add(cacheKey, value);

        return value;
    }

    private static void add(String key, Object item) {
        if (cachedItems.containsKey(key)) {
            throw new RuntimeException("Duplicated key=" + key);
        }

        cachedItems.put(key, new CachedItem(item, System.currentTimeMillis()));
    }
    public static boolean remove(String key) {
        CachedItem cachedItem = cachedItems.remove(key);
        return cachedItem != null;
    }
    public static boolean exists(String key) {
        CachedItem cachedItem = cachedItems.get(key);
        return cachedItem != null;
    }
    private static Object get(String key) {
        CachedItem cachedItem = cachedItems.get(key);
        if (cachedItem == null) {
            return null;
        }

        if (System.currentTimeMillis() - cachedItem.entryDate > 5 * 60 * 1000) {
            cachedItems.remove(key);
            return null;
        }

        return cachedItem.item;
    }

    @FunctionalInterface
    public static interface ValueSupplier {
        Object get() throws Exception;
    }

    private static class CachedItem {
        private Object item;
        private long entryDate;

        public CachedItem(Object item, long entryDate) {
            this.item = item;
            this.entryDate = entryDate;
        }
    }
}
