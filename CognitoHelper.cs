using System;
using Amazon;
using Amazon.Runtime;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net;

namespace AWS
{
    public class CognitoHelper
    {
        private static CognitoHelper instance;
        private AmazonCognitoIdentityProviderClient client;

        public string CurrentUsername { get; set; }
        private string UserAccessToken { get; set; }

        private CognitoHelper()
        {
        }

        public static CognitoHelper Instance
        {
            get
            {
                if (instance == null)
                {
                    instance = new CognitoHelper();
                    instance.InitClient();
                }
                return instance;
            }
        }

        public void InitClient()
        {
            if (client == null)
            {
                client = new AmazonCognitoIdentityProviderClient(
                    new AnonymousAWSCredentials(), RegionEndpoint.USEast1);
            }
        }

        public async Task<string> FindUserAsync(string username)
        {
            try
            {
                var userRequest = new AdminGetUserRequest
                {
                    Username = username,
                    UserPoolId = Constants.POOL_ID
                };
                var response = await client.AdminGetUserAsync(userRequest);
                if (response.HttpStatusCode == HttpStatusCode.OK)
                    return username;
            }
            catch (UserNotConfirmedException e){ Console.WriteLine(e.Message); }
            catch (NotAuthorizedException e) { Console.WriteLine(e.Message); }
            catch (Exception e) { Console.WriteLine(e.Message); }
            return null;
        }

        public async Task<Tuple<int, string>> LoginUserAsync(string username, string password)
        {
            try
            {
                CurrentUsername = username;
                var authRequest = new InitiateAuthRequest
                {
                    AuthFlow = AuthFlowType.USER_PASSWORD_AUTH,
                    ClientId = Constants.POOL_CLIENT_ID
                };
                authRequest.AuthParameters.Add("USERNAME", username);
                authRequest.AuthParameters.Add("PASSWORD", password);

                var authResp = await client.InitiateAuthAsync(authRequest);
                if (authResp.HttpStatusCode == HttpStatusCode.OK)
                {
                    UserAccessToken = authResp.AuthenticationResult.AccessToken;
                    return Tuple.Create<int, string>(1, "Login Success!");
                }
            }
            catch(UserNotConfirmedException e)
            {
                Console.WriteLine(e.Message);
                return Tuple.Create<int, string>(2, e.Message);
            }
            catch (NotAuthorizedException e)
            {
                Console.WriteLine(e.Message);
                return Tuple.Create<int, string>(3, e.Message);
            }
            catch(UserNotFoundException e)
            {
                Console.WriteLine(e.Message);
                return Tuple.Create<int, string>(4, e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return Tuple.Create<int, string>(5, "Invalid username and passowrd!");
        }

        public async Task LogoutUserAsync(string username)
        {
            try
            {
                CurrentUsername = "";
                var signoutRequest = new AdminUserGlobalSignOutRequest
                {
                    Username = username,
                    UserPoolId = Constants.POOL_ID
                };
                var response = await client.AdminUserGlobalSignOutAsync(signoutRequest);
                if(response.HttpStatusCode == HttpStatusCode.OK)
                    UserAccessToken = null;
            }
            catch (UserNotConfirmedException e){ Console.WriteLine(e.Message); }
            catch (NotAuthorizedException e) { Console.WriteLine(e.Message); }
            catch (Exception e) { Console.WriteLine(e.Message); }
        }

        public async Task ForgotPasswordAsync(string username)
        {
            try
            {
                CurrentUsername = username;
                var passowrdRequest = new ForgotPasswordRequest
                {
                    Username = username,
                    ClientId = Constants.POOL_CLIENT_ID
                };
                var response = await client.ForgotPasswordAsync(passowrdRequest);
            }
            catch (UserNotConfirmedException e) { Console.WriteLine(e.Message); }
            catch (NotAuthorizedException e) { Console.WriteLine(e.Message); }
            catch (Exception e) { Console.WriteLine(e.Message); }

        }

        public async Task<Tuple<bool, string>> ConfirmNewPassowrdAsync(string username, string password, string code)
        {
            try
            {
                var passwordRequest = new ConfirmForgotPasswordRequest
                {
                    ClientId = Constants.POOL_CLIENT_ID,
                    Username = username,
                    Password = password,
                    ConfirmationCode = code
                };
                var response = await client.ConfirmForgotPasswordAsync(passwordRequest);
                if (response.HttpStatusCode == HttpStatusCode.OK)
                    return Tuple.Create<bool, string>(true, "New password set successfully!");
            }
            catch (UserNotConfirmedException e) { Console.WriteLine(e.Message); }
            catch (NotAuthorizedException e) { Console.WriteLine(e.Message); }
            catch (Exception e) {
                return Tuple.Create<bool, string>(false, e.Message);
            }

            return Tuple.Create<bool, string>(false, "Could not set new passowrd!");
        }
        
        public async Task<Tuple<bool, string>> SignupUserAsync(string username, string email, string password)
        {
            try
            {
                SignUpRequest signUpRequest = new SignUpRequest()
                {
                    ClientId = Constants.POOL_CLIENT_ID,
                    Password = password,
                    Username = username
                };
                AttributeType emailAttribute = new AttributeType()
                {
                    Name = "email",
                    Value = email
                };
                signUpRequest.UserAttributes.Add(emailAttribute);

                var signUpResult = await client.SignUpAsync(signUpRequest);
                if (signUpResult.HttpStatusCode == HttpStatusCode.OK)
                    return Tuple.Create<bool, string>(true, "User Registered successfully!");
            }
            catch (Exception e)
            {
                return Tuple.Create<bool, string>(false, e.Message);
            }

            return Tuple.Create<bool, string>(false, "Unable to register user!");
        }

        public async Task<Tuple<int, string>> ConfirmSignupAsync(string username, string code)
        {
            try
            {
                ConfirmSignUpRequest confirmRequest = new ConfirmSignUpRequest()
                {
                    Username = username,
                    ClientId = Constants.POOL_CLIENT_ID,
                    ConfirmationCode = code
                };

                var confirmResult = await client.ConfirmSignUpAsync(confirmRequest);
                if (confirmResult.HttpStatusCode == HttpStatusCode.OK)
                    return Tuple.Create<int, string>(1, "Confirmation request successfully!");
            }
            catch (Exception e)
            {
                return Tuple.Create<int, string>(0, e.Message);
            }
            return Tuple.Create<int, string>(-1, "Unable to confirm request!");
        }

        public async Task<Tuple<int, string>> ResendConfirmationCodeAsync(string username)
        {
            try
            {
                var codeRequest = new ResendConfirmationCodeRequest
                {
                    Username = username,
                    ClientId = Constants.POOL_CLIENT_ID
                };

                var codeResult = await client.ResendConfirmationCodeAsync(codeRequest);
                if (codeResult.HttpStatusCode == HttpStatusCode.OK)
                    return Tuple.Create<int, string>(1, "Verification code request sent!");
            }
            catch (Exception e)
            {
                return Tuple.Create<int, string>(0, e.Message);
            }
            return Tuple.Create<int, string>(-1, "Unable to send confirmation code!");
        }

        public async Task<Tuple<int, string>> DeleteUserAccountAsync(string username)
        {
            try
            {
                
                var deleteRequest = new DeleteUserRequest
                {
                    AccessToken = UserAccessToken
                };
                var deleteResult = await client.DeleteUserAsync(deleteRequest);
                if (deleteResult.HttpStatusCode == HttpStatusCode.OK)
                    return Tuple.Create<int, string>(1, "User deleted successfully!");
            }
            catch (Exception e)
            {
                return Tuple.Create<int, string>(0, e.Message);
            }
            return Tuple.Create<int, string>(-1, string.Format("Unable delete user: {0}!", username));
        }
    }
}
