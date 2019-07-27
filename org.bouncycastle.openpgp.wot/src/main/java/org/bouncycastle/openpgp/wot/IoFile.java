package org.bouncycastle.openpgp.wot;

import static java.util.Objects.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class IoFile implements PgpFile {

	private final File file;
	private final String pgpId;

	public IoFile(File file) throws IOException {
		this.file = requireNonNull(file, "file").getCanonicalFile();
		this.pgpId = CanonicalString.canonicalize(file.getParentFile().getPath());
	}

	@Override
	public String getId() {
		return file.getPath();
	}

	public File getFile() {
		return file;
	}

	@Override
	public String getPgpId() {
		return pgpId;
	}

	@Override
	public long getLastModified() {
		return file.lastModified();
	}

	@Override
	public InputStream createInputStream() throws IOException {
		if (file.isFile())
			return new FileInputStream(file);
		else
			return new ByteArrayInputStream(new byte[0]);
	}

	@Override
	public OutputStream createOutputStream() throws IOException {
		return new FileOutputStream(file);
	}

	@Override
	public PgpRandomAccessFile createRandomAccessFile() throws IOException {
		return new IoRandomAccessFile(this);
	}
}
