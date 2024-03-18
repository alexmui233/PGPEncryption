import java.io.File;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.security.InvalidKeyException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class PGPEncryption {

    private String encryptDirectory;
    private String recipient;
    private String encryptFileExtension;

    private PGPEncryption(String encryptDirectory, String recipient, String encryptFileExtension){
        this.encryptDirectory = encryptDirectory;
        this.recipient = recipient;
        this.encryptFileExtension = encryptFileExtension;
    }

    public void encrypt() throws Exception {
        File encryptDirectoryFile = new File(encryptDirectory);
        encryptFilesRecursive(encryptDirectoryFile);
    }

    public void encryptFilesRecursive(File directory) throws Exception{
        File[] fileList = directory.listFiles();

        // Encrypt files
        if (fileList != null){
            for (File file:fileList){
                if (file.isDirectory()) {
                    encryptFilesRecursive(file);
                } else {
                    // Check recipient public key exist
                    Process process = Runtime.getRuntime().exec("gpg --list-key "+recipient);
                    int exitCode = process.waitFor(); 
                    if (exitCode!=0){
                        throw new InvalidKeyException("gpg does not contain recipient public key");
                    }

                    BasicFileAttributeView attributes = Files.getFileAttributeView(file.toPath(), BasicFileAttributeView.class);
                    FileTime creationTime = attributes.readAttributes().creationTime();
                    Instant currentTime = Instant.now();
                    // Check if the file creation time is 15 minutes ago
                    Instant minsago = currentTime.minus(15, ChronoUnit.MINUTES);
                    
                    if (endsWithSubstring(file.getAbsolutePath(), "." + encryptFileExtension)) {
                        if (creationTime.toInstant().isBefore(minsago)) {
                            File gpgfile = new File(file.getAbsolutePath()+".gpg");
                            if (!gpgfile.exists()){
                                String[] cmd = {"gpg","-r",recipient,"--batch","--yes","--trust-model","always","-e","-o","",""};
                                cmd[cmd.length-2] = file.getAbsolutePath()+".gpg";
                                cmd[cmd.length-1] = file.getAbsolutePath();
                                process = Runtime.getRuntime().exec(cmd);
                                if (process.waitFor()==0){
                                    System.out.println("File encrypted {}." + file.getAbsolutePath());
                                }else{
                                    throw new Exception("PGPEncryption process returned failed for file: " + file.getAbsolutePath());
                                }
                            } else {
                                System.out.println("This file has already been encrypted: " + file.getAbsolutePath());
                            }
                            System.out.println("The file was created 15 minutes ago.");
                        } else {
                            System.out.println("The file was not created 15 minutes ago.");
                        }
                    } else {
                        System.out.println("Invalid file extension: " + file.getAbsolutePath());
                    }
                }
            }
        } else {
            System.out.println("No files found in the directory. No encryption performed.");
        }
    }

    public static boolean endsWithSubstring(String text, String suffix) {
        return text != null && suffix != null && text.endsWith(suffix);
    }

    public static void main(String[] args){
        if (args.length < 2) {
            System.out.println("Insufficient arguments provided.");
            System.out.println("Usage: java PGPEncryption <encryptDirectory> <recipient>");
            return;
        }
        
        try{
            PGPEncryption pgpEncryption = new PGPEncryption(args[0], args[1], "afp");           
            pgpEncryption.encrypt();
        }catch (Exception e){
            System.out.println(e.toString());
        }
    }
}