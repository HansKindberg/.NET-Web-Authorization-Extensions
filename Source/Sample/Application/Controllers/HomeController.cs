using System.Threading.Tasks;
using Application.Models;
using Application.Models.Views.Home;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Application.Controllers
{
	public class HomeController : SiteController
	{
		#region Fields

		private const string _permissionAuthorizationFormat = "Authorized by permission \"{0}\".";
		private const string _roleAuthorizationFormat = "Authorized by role {0}.";

		#endregion

		#region Constructors

		public HomeController(IFacade facade) : base(facade) { }

		#endregion

		#region Properties

		protected internal virtual string PermissionAuthorizationFormat => _permissionAuthorizationFormat;
		protected internal virtual string RoleAuthorizationFormat => _roleAuthorizationFormat;

		#endregion

		#region Methods

		public virtual async Task<IActionResult> Index()
		{
			return await Task.FromResult(this.View());
		}

		[Authorize(Roles = "Fifth-role")]
		public virtual async Task<IActionResult> OnlyForFifthRole()
		{
			return await Task.FromResult(this.View("Authorized", new AuthorizedViewModel {Information = string.Format(null, this.RoleAuthorizationFormat, "Fifth-role")}));
		}

		[Authorize("First-permission")]
		public virtual async Task<IActionResult> OnlyForFirstPermission()
		{
			return await Task.FromResult(this.View("Authorized", new AuthorizedViewModel {Information = string.Format(null, this.PermissionAuthorizationFormat, "First-permission")}));
		}

		[Authorize(Roles = "First-role")]
		public virtual async Task<IActionResult> OnlyForFirstRole()
		{
			return await Task.FromResult(this.View("Authorized", new AuthorizedViewModel {Information = string.Format(null, this.RoleAuthorizationFormat, "First-role")}));
		}

		[Authorize(Roles = "Fourth-role")]
		public virtual async Task<IActionResult> OnlyForFourthRole()
		{
			return await Task.FromResult(this.View("Authorized", new AuthorizedViewModel {Information = string.Format(null, this.RoleAuthorizationFormat, "Fourth-role")}));
		}

		[Authorize("Second-permission")]
		public virtual async Task<IActionResult> OnlyForSecondPermission()
		{
			return await Task.FromResult(this.View("Authorized", new AuthorizedViewModel {Information = string.Format(null, this.PermissionAuthorizationFormat, "Second-permission")}));
		}

		[Authorize(Roles = "Second-role")]
		public virtual async Task<IActionResult> OnlyForSecondRole()
		{
			return await Task.FromResult(this.View("Authorized", new AuthorizedViewModel {Information = string.Format(null, this.RoleAuthorizationFormat, "Second-role")}));
		}

		[Authorize("Third-permission")]
		public virtual async Task<IActionResult> OnlyForThirdPermission()
		{
			return await Task.FromResult(this.View("Authorized", new AuthorizedViewModel {Information = string.Format(null, this.PermissionAuthorizationFormat, "Third-permission")}));
		}

		[Authorize(Roles = "Third-role")]
		public virtual async Task<IActionResult> OnlyForThirdRole()
		{
			return await Task.FromResult(this.View("Authorized", new AuthorizedViewModel {Information = string.Format(null, this.RoleAuthorizationFormat, "Third-role")}));
		}

		#endregion
	}
}