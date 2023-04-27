package de.androidcrypto;

public class WriteCyclicFileBuilderBuilder {

    // see https://www.baeldung.com/intellij-idea-java-builders

    private int fileNumber;
    private String content;

    public WriteCyclicFileBuilderBuilder setFileNumber(int fileNumber) {
        this.fileNumber = fileNumber;
        return this;
    }

    public WriteCyclicFileBuilderBuilder setContent(String content) {
        this.content = content;
        return this;
    }

    public WriteCyclicFileBuilder createWriteCyclicFileBuilder() {
        return new WriteCyclicFileBuilder(fileNumber, content);
    }
}