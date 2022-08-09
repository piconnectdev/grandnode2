//Contribiute https://github.com/guilhermesuzuki/DataDeletionCallbackURL/blob/master/DataDeletionCallbackURL/Controllers/SocialNetworkController.cs
using Authentication.Facebook.Models;
using Grand.Business.Core.Interfaces.Authentication;
using Grand.Business.Core.Utilities.Authentication;
using Grand.SharedKernel;
using Grand.Web.Common.Controllers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace Authentication.Facebook.Controllers
{
    public class FacebookAuthenticationController : BasePluginController
    {
        #region Fields

        private readonly IExternalAuthenticationService _externalAuthenticationService;
        private readonly IConfiguration _configuration;

        #endregion

        #region Ctor

        public FacebookAuthenticationController(
            IExternalAuthenticationService externalAuthenticationService,
            IConfiguration configuration)
        {
            _externalAuthenticationService = externalAuthenticationService;
            _configuration = configuration;
        }

        #endregion

        #region Methods

        public IActionResult FacebookLogin(string returnUrl)
        {
            if (!_externalAuthenticationService.AuthenticationProviderIsAvailable(FacebookAuthenticationDefaults.ProviderSystemName))
                throw new GrandException("Facebook authentication module cannot be loaded");

            if (string.IsNullOrEmpty(_configuration["FacebookSettings:AppId"]) || string.IsNullOrEmpty(_configuration["FacebookSettings:AppSecret"]))
                throw new GrandException("Facebook authentication module not configured");

            //configure login callback action
            var authenticationProperties = new AuthenticationProperties {
                RedirectUri = Url.Action("FacebookLoginCallback", "FacebookAuthentication", new { returnUrl = returnUrl })
            };

            return Challenge(authenticationProperties, FacebookDefaults.AuthenticationScheme);
        }

        public async Task<IActionResult> FacebookLoginCallback(string returnUrl)
        {
            //authenticate Facebook user
            var authenticateResult = await HttpContext.AuthenticateAsync(FacebookDefaults.AuthenticationScheme);
            if (!authenticateResult.Succeeded || !authenticateResult.Principal.Claims.Any())
                return RedirectToRoute("Login");

            //create external authentication parameters
            var authenticationParameters = new ExternalAuthParam {
                ProviderSystemName = FacebookAuthenticationDefaults.ProviderSystemName,
                AccessToken = await HttpContext.GetTokenAsync(FacebookDefaults.AuthenticationScheme, "access_token"),
                Email = authenticateResult.Principal.FindFirst(claim => claim.Type == ClaimTypes.Email)?.Value,
                Identifier = authenticateResult.Principal.FindFirst(claim => claim.Type == ClaimTypes.NameIdentifier)?.Value,
                Name = authenticateResult.Principal.FindFirst(claim => claim.Type == ClaimTypes.Name)?.Value,
                Claims = authenticateResult.Principal.Claims.ToList()
            };

            //authenticate Grand user
            return await _externalAuthenticationService.Authenticate(authenticationParameters, returnUrl);
        }


        public IActionResult FacebookSignInFailed(string error_code, string error_message, string state)
        {
            //handle exception and display message to user
            var model = new FailedModel() {
                ErrorCode = error_code,
                ErrorMessage = error_message
            };
            return View(model);
        }

        public async Task<IActionResult> DataDelete()
        {
            string signed_request = Request.Form["signed_request"];
            if (!string.IsNullOrEmpty(signed_request))
            {
                var split = signed_request.Split('.');

                if (string.IsNullOrWhiteSpace(split[0]) == false) split[0] = convert(split[0]);
                if (string.IsNullOrWhiteSpace(split[1]) == false) split[1] = convert(split[1]);

                var dataRaw = Encoding.UTF8.GetString(Convert.FromBase64String(split[1]));

                var json = JObject.Parse(dataRaw);

                var hmac = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(_configuration["FacebookSettings:AppSecret"]));
                var expectedHash = Convert.ToBase64String(hmac.ComputeHash(
                    Encoding.UTF8.GetBytes(signed_request.Split('.')[1]))).Replace('-', '+').Replace('_', '/');

                if (expectedHash != split[0])
                {
                    return BadRequest();
                }
                var identifier = json.GetValue("user_id").ToString();

                var customer = await _externalAuthenticationService.GetCustomer(new ExternalAuthParam() { Identifier = identifier, ProviderSystemName = FacebookAuthenticationDefaults.ProviderSystemName });
                if (customer == null) return BadRequest();

                var externalident = (await _externalAuthenticationService.GetExternalIdentifiers(customer)).FirstOrDefault(x => x.ProviderSystemName == FacebookAuthenticationDefaults.ProviderSystemName);
                if (externalident == null) return BadRequest();

                await _externalAuthenticationService.DeleteExternalAuthentication(externalident);

                if (json != null)
                {
                    return Json(new
                    {
                        url = Url.Action("FacebookInfo", "FacebookAuthentication", new { userid = identifier }, HttpContext.Request.Scheme),
                        confirmation_code = identifier,
                    });
                }
            }

            return BadRequest();

            static string convert(string value)
            {
                var mod4 = value.Length % 4;
                if (mod4 > 0) value += new string('=', 4 - mod4);
                value = value.Replace('-', '+').Replace('_', '/');
                return value;
            }
        }

        [HttpGet]
        public IActionResult FacebookInfo(string userid)
        {
            return RedirectToRoute("HomePage");
        }


        #endregion
    }
}