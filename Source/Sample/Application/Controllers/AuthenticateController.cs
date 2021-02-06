using System;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Application.Models;
using Application.Models.Web.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using RegionOrebroLan.Logging.Extensions;

namespace Application.Controllers
{
	public class AuthenticateController : SiteController
	{
		#region Constructors

		public AuthenticateController(IFacade facade) : base(facade) { }

		#endregion

		#region Methods

		public virtual async Task<IActionResult> Callback()
		{
			var authenticateResult = await this.HttpContext.AuthenticateAsync(AuthenticationSchemes.Intermediate);

			if(!authenticateResult.Succeeded)
				throw new InvalidOperationException("Authentication error.", authenticateResult.Failure);

			// ReSharper disable All

			var returnUrl = this.ResolveAndValidateReturnUrl(authenticateResult.Properties.Items[AuthenticationKeys.ReturnUrl]);

			var authenticationProperties = new AuthenticationProperties();

			await this.HttpContext.SignInAsync(AuthenticationSchemes.Cookie, authenticateResult.Principal, authenticationProperties);

			// ReSharper restore All

			await this.HttpContext.SignOutAsync(AuthenticationSchemes.Intermediate);

			return this.Redirect(returnUrl);
		}

		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		[SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
		public virtual async Task<IActionResult> Windows(string returnUrl)
		{
			returnUrl = this.ResolveAndValidateReturnUrl(returnUrl);

			// Check if windows-authentication has already been requested and succeeded.
			var authenticateResult = await this.HttpContext.AuthenticateAsync(AuthenticationSchemes.Windows);

			// ReSharper disable All
			if(authenticateResult.Principal is WindowsPrincipal windowsPrincipal)
			{
				var authenticationProperties = new AuthenticationProperties
				{
					RedirectUri = this.Url.Action(nameof(this.Callback))
				};

				authenticationProperties.SetString(AuthenticationKeys.ReturnUrl, returnUrl);
				authenticationProperties.SetString(AuthenticationKeys.Scheme, AuthenticationSchemes.Windows);

				var claims = windowsPrincipal.Claims
					.Where(claim =>
						!claim.Type.Equals(ClaimTypes.DenyOnlySid, StringComparison.OrdinalIgnoreCase) &&
						!claim.Type.Equals(ClaimTypes.GroupSid, StringComparison.OrdinalIgnoreCase) &&
						!claim.Type.Equals(ClaimTypes.PrimaryGroupSid, StringComparison.OrdinalIgnoreCase)
					)
					.ToList();

				claims.Add(new Claim(ClaimTypes.NameIdentifier, "1"));

				try
				{
					var securityIdentifier = claims.FirstOrDefault(claim => claim.Type.Equals(ClaimTypes.PrimarySid, StringComparison.OrdinalIgnoreCase))?.Value;

					using(var principalContext = new PrincipalContext(ContextType.Domain))
					{
						var userPrincipal = UserPrincipal.FindByIdentity(principalContext, IdentityType.Sid, securityIdentifier);

						if(userPrincipal == null)
							throw new InvalidOperationException($"User-principal with security-identifier \"{securityIdentifier}\" was not found.");

						var userPrincipalName = userPrincipal.UserPrincipalName;

						claims.Add(new Claim(ClaimTypes.Upn, userPrincipalName));
					}
				}
				catch(Exception exception)
				{
					this.Logger.LogErrorIfEnabled(exception, "Could not get user-principal-name.");
				}

				var claimsIdentity = new ClaimsIdentity(claims, windowsPrincipal.Identity.AuthenticationType);

				await this.HttpContext.SignInAsync(AuthenticationSchemes.Intermediate, new ClaimsPrincipal(claimsIdentity), authenticationProperties);

				return this.Redirect(authenticationProperties.RedirectUri);
			}
			// ReSharper restore All

			// Trigger windows-authentication. Since windows-authentication don't support the redirect uri, this URL is re-triggered when we call challenge.
			return this.Challenge(AuthenticationSchemes.Windows);
		}

		#endregion
	}
}