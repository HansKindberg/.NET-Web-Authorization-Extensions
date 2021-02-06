using System;
using System.Diagnostics.CodeAnalysis;
using IdentityModel;
using Microsoft.AspNetCore.Authorization;

namespace HansKindberg.Web.Authorization.Configuration
{
	[CLSCompliant(false)]
	public class ExtendedAuthorizationOptions : AuthorizationOptions
	{
		#region Properties

		public virtual bool MiddlewareEnabled { get; set; } = true;
		public virtual string NameClaimType { get; set; } = JwtClaimTypes.Name;
		public virtual string PermissionClaimType { get; set; } = "permission";
		public virtual PermissionsOptions Permissions { get; set; } = new PermissionsOptions();

		[SuppressMessage("Naming", "CA1721:Property names should not match get methods")]
		public virtual PolicyOptions Policy { get; set; } = new PolicyOptions();

		public virtual bool PolicyProviderEnabled { get; set; } = true;
		public virtual string RoleClaimType { get; set; } = JwtClaimTypes.Role;
		public virtual RolesOptions Roles { get; set; } = new RolesOptions();
		public virtual bool ThrowConfigurationExceptions { get; set; } = true;

		#endregion
	}
}