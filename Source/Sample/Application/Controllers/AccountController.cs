using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Application.Models;
using Application.Models.Views.Account;
using Application.Models.Web.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Application.Controllers
{
	[Authorize]
	public class AccountController : SiteController
	{
		#region Constructors

		public AccountController(IFacade facade) : base(facade) { }

		#endregion

		#region Methods

		[AllowAnonymous]
		public virtual async Task<IActionResult> AccessDenied()
		{
			return await Task.FromResult(this.View());
		}

		protected internal virtual async Task<SignInViewModel> CreateSignInViewModelAsync(string returnUrl)
		{
			return await Task.FromResult(new SignInViewModel
			{
				Form =
				{
					ReturnUrl = returnUrl
				}
			});
		}

		protected internal virtual async Task<SignInViewModel> CreateSignInViewModelAsync(SignInForm form)
		{
			if(form == null)
				throw new ArgumentNullException(nameof(form));

			var model = await this.CreateSignInViewModelAsync(form.ReturnUrl);

			model.Form = form;

			return model;
		}

		protected internal virtual async Task<SignOutViewModel> CreateSignOutViewModelAsync()
		{
			return await Task.FromResult(new SignOutViewModel
			{
				Confirm = this.User?.Identity != null && this.User.Identity.IsAuthenticated
			});
		}

		public virtual async Task<IActionResult> Index()
		{
			var model = new AccountViewModel
			{
				UserName = this.User?.Identity?.Name
			};

			var authenticateResult = await this.HttpContext.AuthenticateAsync();

			if(authenticateResult.Properties != null)
			{
				foreach(var (key, value) in authenticateResult.Properties.Items)
				{
					model.AuthenticationProperties.Add(key, value);
				}
			}

			foreach(var claim in this.User?.Claims ?? Enumerable.Empty<Claim>())
			{
				model.Claims.Add(claim);
			}

			var policy = await this.Facade.AuthorizationResolver.GetPolicyAsync(this.User);

			foreach(var permission in policy.Permissions)
			{
				model.Permissions.Add(permission);
			}

			foreach(var role in policy.Roles)
			{
				model.Roles.Add(role);
			}

			return await Task.FromResult(this.View(model));
		}

		[AllowAnonymous]
		public virtual async Task<IActionResult> SignIn(string returnUrl)
		{
			returnUrl = this.ResolveAndValidateReturnUrl(returnUrl);

			var model = await this.CreateSignInViewModelAsync(returnUrl);

			return this.View(model);
		}

		[AllowAnonymous]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public virtual async Task<IActionResult> SignIn(SignInForm form)
		{
			if(form == null)
				throw new ArgumentNullException(nameof(form));

			form.ReturnUrl = this.ResolveAndValidateReturnUrl(form.ReturnUrl);

			if(form.Cancel)
				return this.Redirect(form.ReturnUrl);

			if(this.ModelState.IsValid)
			{
				if(!string.IsNullOrWhiteSpace(form.UserName))
				{
					var nameIdentifier = string.Equals(form.UserName, "alice", StringComparison.OrdinalIgnoreCase) ? 2 : string.Equals(form.UserName, "bob", StringComparison.OrdinalIgnoreCase) ? 3 : 4;

					var claims = new List<Claim>
					{
						new(ClaimTypes.Name, form.UserName),
						new(ClaimTypes.NameIdentifier, nameIdentifier.ToString(CultureInfo.InvariantCulture))
					};

					var authenticationProperties = new AuthenticationProperties();
					var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Fake"));

					await this.HttpContext.SignInAsync(AuthenticationSchemes.Cookie, principal, authenticationProperties);

					return this.Redirect(form.ReturnUrl);
				}

				this.ModelState.AddModelError(nameof(SignInForm.UserName), "Invalid user-name.");
			}

			var model = await this.CreateSignInViewModelAsync(form);

			return await Task.FromResult(this.View(model));
		}

		[AllowAnonymous]
		public virtual async Task<IActionResult> SignOut(string _)
		{
			var model = await this.CreateSignOutViewModelAsync();

			if(!model.Confirm)
				return await this.SignOut(model.Form);

			return this.View(model);
		}

		[AllowAnonymous]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public virtual async Task<IActionResult> SignOut(SignOutForm form)
		{
			if(form == null)
				throw new ArgumentNullException(nameof(form));

			form.ReturnUrl = this.ResolveAndValidateReturnUrl(form.ReturnUrl);

			if(this.User?.Identity != null && this.User.Identity.IsAuthenticated)
				await this.HttpContext.SignOutAsync(AuthenticationSchemes.Cookie);

			return this.Redirect(form.ReturnUrl);
		}

		#endregion
	}
}