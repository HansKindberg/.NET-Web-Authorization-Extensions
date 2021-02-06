using System;
using System.Collections.Generic;
using System.Security.Principal;
using HansKindberg.Web.Authorization.Configuration;

namespace IntegrationTests.Helpers.Security.Principal.Extensions
{
#if NET5_0
	[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
	public static class WindowsIdentityExtension
	{
		#region Methods

		public static ISet<string> GetRoles(this WindowsIdentity windowsIdentity, WindowsRolesOptions options = null)
		{
			if(windowsIdentity == null)
				throw new ArgumentNullException(nameof(windowsIdentity));

			return windowsIdentity.Groups.AsRoles(options);
		}

		#endregion
	}
}