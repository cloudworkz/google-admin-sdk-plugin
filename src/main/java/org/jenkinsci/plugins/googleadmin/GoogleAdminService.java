package org.jenkinsci.plugins.googleadmin;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.admin.directory.Directory;
import com.google.api.services.admin.directory.DirectoryScopes;
import com.google.api.services.admin.directory.model.Member;
import com.google.api.services.admin.directory.model.Members;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GoogleAdminService {

  private final static Logger logger = LoggerFactory.getLogger(GoogleAdminService.class);

  private final String applicationName = "Google Admin Service @ Jenkins";

  private final JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();

  private final String credentialsFolder;

  private final String clientSecretFile;

  private final Directory service;

  /**
   * Global instance of the scopes required by this quickstart.
   * If modifying these scopes, delete your previously saved credentials folder at /secret.
   */
  private final List<String> scopes = Arrays.asList(
      DirectoryScopes.ADMIN_DIRECTORY_USER_READONLY,
      DirectoryScopes.ADMIN_DIRECTORY_GROUP_READONLY
  );


  GoogleAdminService(String credentialsFolder, String clientSecretFile, String adminAccountEmail) throws GeneralSecurityException, IOException {
    this.credentialsFolder = credentialsFolder;
    this.clientSecretFile = clientSecretFile;

    final NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();

    service = new Directory
        .Builder(httpTransport, jsonFactory, getCredentials(httpTransport, adminAccountEmail))
        .setApplicationName(applicationName).build();
  }

  private Credential getCredentials(final NetHttpTransport httpTransport, String adminAccountEmail) throws IOException {
    InputStream in = new FileInputStream(clientSecretFile);
    GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(jsonFactory, new InputStreamReader(in, StandardCharsets.UTF_8));

    GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow
        .Builder(httpTransport, jsonFactory, clientSecrets, scopes)
        .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(credentialsFolder)))
        .setAccessType("offline").build();

    return new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize(adminAccountEmail);
  }

  public List<String> getGroupMembers(String groupKey) throws IOException {
    Members members = service.members().list(groupKey).execute();
    if (members == null || members.size() == 0) {
        return new ArrayList<>();
    } else {
      List<String> emails = new ArrayList<>();
      for (Member member : members.getMembers()) {
        emails.add(member.getEmail());
      }
      return emails;
    }
  }

  public static void main(String[] args) {
    try {
      List<String> members = new GoogleAdminService(".credentials/", ".credentials/credentials.json", "admin@test.com").getGroupMembers("group@test.com");
      logger.info("got members {}", members);
    } catch (Throwable t) {
      logger.error("error fetching members", t);
    }
  }
}
