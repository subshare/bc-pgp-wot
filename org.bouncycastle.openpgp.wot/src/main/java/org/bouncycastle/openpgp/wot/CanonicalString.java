package org.bouncycastle.openpgp.wot;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

/**
 * Utility class making {@code String} instances canonical in the memory.
 * @author Marco หงุ่ยตระกูล-Schulze - marco at codewizards dot co
 */
public final class CanonicalString {

//	private static final WeakHashMap<String, WeakReference<String>> canonicalStringMap = new WeakHashMap<>();

	private CanonicalString() {
	}

	/**
	 * Return an instance equal to the given String but guaranteed to be unique in memory.
	 * <p>
	 * Since Java 7, the {@link String#intern()} method now manages a garbage-collected pool.
	 * Before Java 7, the pool was not garbage-collected and could easily overflow (it was even
	 * a fixed-size pretty small map). Therefore, this method is currently an alias to
	 * {@link String#intern()}. If there are any issues with this approach, we might easily switch
	 * to our own implementation again.
	 *
	 * @param string the String to be canonicalized. Must not be <code>null</code>.
	 * @return a canonical version of the given String. Never <code>null</code>.
	 */
	public static synchronized String canonicalize(final String string) {
		assertNotNull(string, "string");
//		final WeakReference<String> ref = canonicalStringMap.get(string);
//		String canonicalString = ref == null ? null : ref.get();
//		if (canonicalString == null) {
//			canonicalString = string;
//			canonicalStringMap.put(canonicalString, new WeakReference<String>(canonicalString));
//		}
//		return canonicalString;

		// According to http://java-performance.info/string-intern-in-java-6-7-8/
		// the Strings interned by String.intern() are garbage-collected since Java 7.
		// Hence, we don't need our own implementation using WeakReference anymore.

		return string.intern();
	}
}
