package com.modernisc.security.keycloak.users.cbank;

import java.util.HashMap;

public class MyCache {
    private static HashMap<String, CachedItem> cachedItems = new HashMap<>();

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

    private static Object get(String key) {
        CachedItem cachedItem = cachedItems.get(key);
        if (cachedItem == null) {
            return null;
        }

        if (System.currentTimeMillis() - cachedItem.entryDate > 2 * 60 * 1000) {
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
