package unimelb.bitbox.util;

import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;

import java.io.IOException;

public interface FileSystemObserver {
    public void processFileSystemEvent(FileSystemEvent fileSystemEvent) throws IOException;
}