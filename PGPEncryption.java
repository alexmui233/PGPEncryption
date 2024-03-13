import java.io.File;
import java.security.InvalidKeyException;

public class PGPEncryption {

    private String encryptDirectory;
    private String recipient;
    private String encryptFileExtension;

    private PGPEncryption(String encryptDirectory, String recipient, String encryptFileExtension){
        this.encryptDirectory = encryptDirectory;
        this.recipient = recipient;
        this.encryptFileExtension = encryptFileExtension;
    }

    public void encrypt() throws Exception{
        File encryptDirectoryfile = new File(encryptDirectory);
        File[] fileList = encryptDirectoryfile.listFiles();

        // Check recipient public key exist
        Process process = Runtime.getRuntime().exec("gpg --list-key "+recipient);
        int exitCode = process.waitFor(); 
        if (exitCode!=0){
            throw new InvalidKeyException("gpg does not contain recipient public key");
        }

        // Encrypt files
        String[] cmd = {"gpg","-r",recipient,"--batch","--yes","--trust-model","always","-e","-o","",""};
        if (fileList != null){
            for (File file:fileList){
                if (endsWithSubstring(file.getAbsolutePath(), "." + encryptFileExtension)) {
                    File gpgfile = new File(file.getAbsolutePath()+".gpg");
                    if (!gpgfile.exists()){
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
                } else {
                    System.out.println("Invalid file extension: " + file.getAbsolutePath());
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
        
        try{
            PGPEncryption pgpEncryption = new PGPEncryption(args[0], args[1], "afp");           
            pgpEncryption.encrypt();
        }catch (Exception e){
            System.out.println(e.toString());
        }
        
    }
}
