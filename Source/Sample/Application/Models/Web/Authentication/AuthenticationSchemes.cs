using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Server.IIS;

namespace Application.Models.Web.Authentication
{
	public static class AuthenticationSchemes
	{
		#region Fields

		public const string Cookie = CookieAuthenticationDefaults.AuthenticationScheme;
		public const string Intermediate = "Intermediate";
		public const string Windows = IISServerDefaults.AuthenticationScheme;

		#endregion
	}
}