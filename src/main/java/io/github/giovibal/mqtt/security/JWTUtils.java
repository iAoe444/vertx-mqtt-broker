package io.github.giovibal.mqtt.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JWTUtils {
    public static boolean isJWT(String jwt) {
        try {
            String[] jwtParts = jwt.split("\\.", 3);

            byte[] h,p;
            h = Base64.getUrlDecoder().decode(jwtParts[0]);
            p = Base64.getUrlDecoder().decode(jwtParts[1]);
            return h.length>0 && p.length>0;

        } catch (Throwable e) {
            return false;
        }
    }
    public static String decodeJWTPayoad(String jwt) {
        try {
            String[] jwtParts = jwt.split("\\.", 3);

            String jwtPayload = jwtParts[1];
            byte[] payload = Base64.getUrlDecoder().decode(jwtPayload);
            return new String(payload, StandardCharsets.UTF_8);
        } catch (Throwable e) {
            return "";
        }
    }
    public static String decodeJWTHeader(String jwt) {
        try {
            String[] jwtParts = jwt.split("\\.", 3);

            String jwtHeader = jwtParts[0];
            byte[] header = Base64.getUrlDecoder().decode(jwtHeader);
            return new String(header, StandardCharsets.UTF_8);
        } catch (Throwable e) {
            return "";
        }
    }


    public static void main(String[] args) {
        System.out.printf("JWT header  => %s\n", JWTUtils.decodeJWTHeader("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJqOXFtS05hdXV5bzBYTExVa2VBR1RzTDdkWXhta2xlSEZPYXRUOGVnZTdJIn0.eyJqdGkiOiI2YmQzODhjNi1hOWExLTQ4NTYtOGVmZC01NjEzMTk3OTAxNjAiLCJleHAiOjE1NjcyNTQ1MjMsIm5iZiI6MCwiaWF0IjoxNTY1OTU4NTIzLCJpc3MiOiJodHRwczovL2lkcC5zbWFydHBsYXRmb3JtLmlvL2F1dGgvcmVhbG1zL3NwIiwiYXVkIjoiZGFzaGJvYXJkIiwic3ViIjoiNTc2NjNmZmMtOTY0OC00ZTA4LWIyMzEtZDYyNjdlZDQwN2VmIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZGFzaGJvYXJkIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiZmU1NjdiZjAtMGQzOC00YjA5LWJiOTAtN2FkZjc4ZWZkODJhIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rhc2hib2FyZC5zbWFydHBsYXRmb3JtLmlvIiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiaHR0cHM6Ly9kYXNoYm9hcmQuZWltd2FyZS5pdCIsImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsibWVjY2FybmkubGV2b25pLml0IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJwb3J0aW5lcmlhQG1lY2Nhcm5pLmxldm9uaS5pdCJ9.l8cqqmXYknXnpYqUtD0-EqGINqqjboio1KNt0SiKEetyRatYpT8SAwKdZvb7zZbYWV0vHLT3QnNDNcpdyNbDgI1u4aY7dZTjil0tnoqTFRGFM4XLkmAXAADNkrBTI0iw-JFBlW37WIhmKE6LR6IwCRlFbd3-IylH_kgN35pSIdpaZV0dFLR4M2dnQpxHvVAihyKoiYI6eNN2YkcCxqIx5JK3bnVxuWHX_bOBOOKQ_boiBG0BlZx1_mOvpqj3NL-dgYv87bidqeXlaou42RsBJhG1KCLrDOtKhmMuKhbk9Z9fVoDfHJHdXFrZzaO-WauuavgIOvwQ3Th50Wt0utXT_A"));
        System.out.printf("JWT paylaod => %s\n", JWTUtils.decodeJWTPayoad("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJqOXFtS05hdXV5bzBYTExVa2VBR1RzTDdkWXhta2xlSEZPYXRUOGVnZTdJIn0.eyJqdGkiOiI2YmQzODhjNi1hOWExLTQ4NTYtOGVmZC01NjEzMTk3OTAxNjAiLCJleHAiOjE1NjcyNTQ1MjMsIm5iZiI6MCwiaWF0IjoxNTY1OTU4NTIzLCJpc3MiOiJodHRwczovL2lkcC5zbWFydHBsYXRmb3JtLmlvL2F1dGgvcmVhbG1zL3NwIiwiYXVkIjoiZGFzaGJvYXJkIiwic3ViIjoiNTc2NjNmZmMtOTY0OC00ZTA4LWIyMzEtZDYyNjdlZDQwN2VmIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZGFzaGJvYXJkIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiZmU1NjdiZjAtMGQzOC00YjA5LWJiOTAtN2FkZjc4ZWZkODJhIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rhc2hib2FyZC5zbWFydHBsYXRmb3JtLmlvIiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiaHR0cHM6Ly9kYXNoYm9hcmQuZWltd2FyZS5pdCIsImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsibWVjY2FybmkubGV2b25pLml0IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJwb3J0aW5lcmlhQG1lY2Nhcm5pLmxldm9uaS5pdCJ9.l8cqqmXYknXnpYqUtD0-EqGINqqjboio1KNt0SiKEetyRatYpT8SAwKdZvb7zZbYWV0vHLT3QnNDNcpdyNbDgI1u4aY7dZTjil0tnoqTFRGFM4XLkmAXAADNkrBTI0iw-JFBlW37WIhmKE6LR6IwCRlFbd3-IylH_kgN35pSIdpaZV0dFLR4M2dnQpxHvVAihyKoiYI6eNN2YkcCxqIx5JK3bnVxuWHX_bOBOOKQ_boiBG0BlZx1_mOvpqj3NL-dgYv87bidqeXlaou42RsBJhG1KCLrDOtKhmMuKhbk9Z9fVoDfHJHdXFrZzaO-WauuavgIOvwQ3Th50Wt0utXT_A"));
        System.out.printf("JWT fake => %s\n", JWTUtils.decodeJWTPayoad("fake"));
        System.out.printf("JWT is JWT => %s\n", JWTUtils.isJWT("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJqOXFtS05hdXV5bzBYTExVa2VBR1RzTDdkWXhta2xlSEZPYXRUOGVnZTdJIn0.eyJqdGkiOiI2YmQzODhjNi1hOWExLTQ4NTYtOGVmZC01NjEzMTk3OTAxNjAiLCJleHAiOjE1NjcyNTQ1MjMsIm5iZiI6MCwiaWF0IjoxNTY1OTU4NTIzLCJpc3MiOiJodHRwczovL2lkcC5zbWFydHBsYXRmb3JtLmlvL2F1dGgvcmVhbG1zL3NwIiwiYXVkIjoiZGFzaGJvYXJkIiwic3ViIjoiNTc2NjNmZmMtOTY0OC00ZTA4LWIyMzEtZDYyNjdlZDQwN2VmIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZGFzaGJvYXJkIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiZmU1NjdiZjAtMGQzOC00YjA5LWJiOTAtN2FkZjc4ZWZkODJhIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rhc2hib2FyZC5zbWFydHBsYXRmb3JtLmlvIiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiaHR0cHM6Ly9kYXNoYm9hcmQuZWltd2FyZS5pdCIsImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsibWVjY2FybmkubGV2b25pLml0IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJwb3J0aW5lcmlhQG1lY2Nhcm5pLmxldm9uaS5pdCJ9.l8cqqmXYknXnpYqUtD0-EqGINqqjboio1KNt0SiKEetyRatYpT8SAwKdZvb7zZbYWV0vHLT3QnNDNcpdyNbDgI1u4aY7dZTjil0tnoqTFRGFM4XLkmAXAADNkrBTI0iw-JFBlW37WIhmKE6LR6IwCRlFbd3-IylH_kgN35pSIdpaZV0dFLR4M2dnQpxHvVAihyKoiYI6eNN2YkcCxqIx5JK3bnVxuWHX_bOBOOKQ_boiBG0BlZx1_mOvpqj3NL-dgYv87bidqeXlaou42RsBJhG1KCLrDOtKhmMuKhbk9Z9fVoDfHJHdXFrZzaO-WauuavgIOvwQ3Th50Wt0utXT_A"));
        System.out.printf("JWT is JWT => %s\n", JWTUtils.isJWT("fake"));
    }
}
