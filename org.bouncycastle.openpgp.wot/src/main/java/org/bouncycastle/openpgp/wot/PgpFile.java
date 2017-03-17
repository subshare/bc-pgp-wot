package org.bouncycastle.openpgp.wot;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A {@code PgpFile} references a file (or a BLOB or similar storage) holding PGP binary data.
 * @author Marco หงุ่ยตระกูล-Schulze - marco at codewizards dot co
 */
public interface PgpFile {
	/**
	 * Gets the fully qualified (or canonical) path of the file.
	 * @return
	 */
	String getId();

	/**
	 * Gets the <i>canonical</i> path to the ".gnupg" directory, when using the file system, or a corresponding unique
	 * identifier for the entire key ring (containing pubring, secring and other files).
	 * <p>
	 * <b>Important implementation notes:</b> This must be a canonical {@code String} obtained from
	 * {@link CanonicalString#canonicalize(String)} during the creation of this {@code PgpFile} instance!
	 * Furthermore, there must be a strong reference from this {@code PgpFile} guaranteeing this String
	 * to not be garbage-collected while the {@code PgpFile} is still used!
	 * @return the unique identifier of the key ring.
	 */
	String getPgpId();

	/**
	 * Gets the timestamp when the content of this {@code PgpFile} was last modified.
	 * <p>
	 * When using a {@link File}, this should be equivalent to {@link File#lastModified()}.
	 * @return the timestamp when the content of this {@code PgpFile} was last modified.
	 */
	long getLastModified();

	InputStream createInputStream() throws IOException;

	OutputStream createOutputStream() throws IOException;

	PgpRandomAccessFile createRandomAccessFile() throws IOException;
}
