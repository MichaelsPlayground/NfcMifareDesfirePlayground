package de.androidcrypto;

public class WriteCyclicFileBuilder {

    // see https://www.baeldung.com/intellij-idea-java-builders

    private int fileNumber;
    private final byte[] offsetZero = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write to the beginning
    private String content;

    public WriteCyclicFileBuilder(int fileNumber, String content) {
        this.fileNumber = fileNumber;
        this.content = content;
    }


    /*
byte[] offsetZero = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write to the beginning
                    String contentString = "Entry from " + Utils.getTimestamp(); // timestamp is 19 characters long
                    int contentLengthInt = contentString.length();
                    // todo be more universal with this. The created record size is 32 so this data is fitting into one record
                    byte[] contentLength = new byte[]{(byte) (contentLengthInt & 0xFF), (byte) 0x00, (byte) 0x00};
                    byte[] content = contentString.getBytes(StandardCharsets.UTF_8);
                    byte[] payloadWriteCyclicFile = new byte[(contentLengthInt + 7)];
                    payloadWriteCyclicFile[0] = desFileNumberCyclic;
                    System.arraycopy(offsetZero, 0, payloadWriteCyclicFile, 1, 3);
                    System.arraycopy(contentLength, 0, payloadWriteCyclicFile, 4, 3);
                    System.arraycopy(content, 0, payloadWriteCyclicFile, 7, contentLengthInt);
                    writeToUiAppend(readResult, printData("payloadWriteCyclicFile", payloadWriteCyclicFile));
     */
}
