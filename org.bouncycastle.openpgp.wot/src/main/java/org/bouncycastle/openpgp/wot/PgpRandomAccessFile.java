package org.bouncycastle.openpgp.wot;

import java.io.EOFException;
import java.io.IOException;

public interface PgpRandomAccessFile extends AutoCloseable {

	@Override
	void close() throws IOException;

	void flush() throws IOException;

	long getLength() throws IOException;

	void seek(long pos) throws IOException;

	void readFully(byte[] buf) throws EOFException, IOException;

	void write(byte[] buf) throws IOException;

}
