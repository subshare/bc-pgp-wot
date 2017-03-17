package org.bouncycastle.openpgp.wot;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IoRandomAccessFile implements PgpRandomAccessFile {
	private static final Logger logger = LoggerFactory.getLogger(IoRandomAccessFile.class);

	private final IoFile ioFile;
	private final File file;
	private final RandomAccessFile raf;
	private final FileLock fileLock;

	public IoRandomAccessFile(IoFile ioFile) throws IOException {
		this.ioFile = assertNotNull(ioFile, "ioFile");
		this.file = assertNotNull(this.ioFile.getFile(), "ioFile.file");

		RandomAccessFile raf = null;
        FileLock fileLock = null;
        try
        {
            raf = new RandomAccessFile(file, "rw");

            // Try to lock the file for 60 seconds - using tryLock() instead of lock(), because I ran
            // into exceptions already, even though lock() should wait according to javadoc.
            final int timeoutMillis = 60 * 1000;
            final int sleepMillis = 500;
            final int tryCount = timeoutMillis / sleepMillis;
            for (int i = 0; i < tryCount; ++i)
            {
                if (fileLock == null && i != 0) {
                    logger.warn("Locking file '{}' failed. Retrying.", file.getAbsolutePath());
                    try
                    {
                        Thread.sleep(sleepMillis);
                    } catch (InterruptedException e)
                    {
                        doNothing(); // ignore
                    }
                }

                try
                {
                    fileLock = raf.getChannel().tryLock();
                } catch (OverlappingFileLockException y)
                {
                    doNothing(); // ignore (it's quite strange that *try*Lock() might still throw this exception at all)
                }
                if (fileLock != null)
                    break;
            }

            if (fileLock == null)
                fileLock = raf.getChannel().lock();

        } finally {
            // If opening the file succeeded, but locking it failed, we must close the RandomAccessFile now.
            if (fileLock == null && raf != null) {
                try {
                    // We only come here, if there's currently an exception flying. Hence, we close the file
                    // inside this new try-catch-block in order to prevent the primary exception from being
                    // lost. A new exception otherwise would suppress the primary exception.
                    raf.close();
                } catch (Exception e) {
                    logger.warn("Closing file failed: " + e, e);
                }
            }
        }
        this.raf = raf;
        this.fileLock = fileLock;
	}

	@Override
	public void close() throws IOException {
		fileLock.release();
        raf.close();
	}

	@Override
	public void flush() throws IOException {
		raf.getFD().sync();
	}

	@Override
	public long getLength() throws IOException {
		return raf.length();
	}

	@Override
	public void seek(long pos) throws IOException {
		raf.seek(pos);
	}

	@Override
	public void readFully(byte[] buf) throws EOFException, IOException {
		raf.readFully(buf);
	}

	@Override
	public void write(byte[] buf) throws IOException {
		raf.write(buf);
	}
}
