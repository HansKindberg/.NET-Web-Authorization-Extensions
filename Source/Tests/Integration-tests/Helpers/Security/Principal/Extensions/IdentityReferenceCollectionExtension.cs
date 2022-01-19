using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using HansKindberg.Web.Authorization.Configuration;

namespace IntegrationTests.Helpers.Security.Principal.Extensions
{
	public static class IdentityReferenceCollectionExtension
	{
		#region Methods

#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
		public static ISet<string> AsRoles(this IdentityReferenceCollection identityReferences, WindowsRolesOptions options = null)
		{
			if(identityReferences == null)
				throw new ArgumentNullException(nameof(identityReferences));

			options ??= new WindowsRolesOptions();

			// ReSharper disable AssignNullToNotNullAttribute
			var securityIdentifiers = identityReferences.Cast<SecurityIdentifier>();
			// ReSharper restore AssignNullToNotNullAttribute

			if(!options.BuiltInRolesEnabled)
				securityIdentifiers = securityIdentifiers.Where(securityIdentifier => securityIdentifier.AccountDomainSid != null);

			identityReferences = new IdentityReferenceCollection();

			foreach(var securityIdentifier in securityIdentifiers)
			{
				identityReferences.Add(securityIdentifier);
			}

			// ReSharper disable AssignNullToNotNullAttribute
			var roles = identityReferences.Translate(typeof(NTAccount)).Select(ntAccount => ntAccount.Value);
			// ReSharper restore AssignNullToNotNullAttribute

			if(!options.MachineRolesEnabled)
				roles = roles.Where(role => !role.StartsWith($"{Environment.MachineName}\\", StringComparison.OrdinalIgnoreCase));

			return new SortedSet<string>(roles, StringComparer.OrdinalIgnoreCase);
		}

		#endregion
	}
}