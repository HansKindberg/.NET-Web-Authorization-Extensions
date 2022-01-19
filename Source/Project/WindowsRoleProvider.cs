using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using HansKindberg.Web.Authorization.Configuration;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.Logging.Extensions;

namespace HansKindberg.Web.Authorization
{
#if NET5_0_OR_GREATER
	[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
	[CLSCompliant(false)]
	public class WindowsRoleProvider : RoleProvider
	{
		#region Fields

		private static readonly string _cacheKeyPrefix = $"{typeof(WindowsRoleProvider).FullName}:";

		#endregion

		#region Constructors

		public WindowsRoleProvider(IMemoryCache cache, IClaimsPrincipalHelper claimsPrincipalHelper, ILoggerFactory loggerFactory, IOptionsMonitor<ExtendedAuthorizationOptions> optionsMonitor) : base(claimsPrincipalHelper, loggerFactory, optionsMonitor)
		{
			this.Cache = cache ?? throw new ArgumentNullException(nameof(cache));
		}

		#endregion

		#region Properties

		protected internal virtual IMemoryCache Cache { get; }
		protected internal virtual string CacheKeyPrefix => _cacheKeyPrefix;
		protected internal virtual object CacheLock { get; } = new object();

		#endregion

		#region Methods

		protected internal virtual async Task<string> CreateCacheKeyAsync(ClaimsPrincipal claimsPrincipal)
		{
			if(claimsPrincipal == null)
				throw new ArgumentNullException(nameof(claimsPrincipal));

			var identifiers = new List<string>();

			if(claimsPrincipal is WindowsPrincipal windowsPrincipal)
			{
				identifiers.AddRange(windowsPrincipal.Identities.Select(identity => identity.Name));
			}
			else
			{
				var userPrincipalNameClaims = await this.ClaimsPrincipalHelper.GetUserPrincipalNameClaimsAsync(claimsPrincipal);
				identifiers.AddRange(userPrincipalNameClaims.Select(userPrincipalNameClaim => userPrincipalNameClaim.Value));
			}

			return $"{this.CacheKeyPrefix}{string.Join(",", identifiers)}".ToUpperInvariant();
		}

		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		protected internal override async Task<ISet<string>> GetRolesInternalAsync(ClaimsPrincipal claimsPrincipal)
		{
			// ReSharper disable InvertIf
			if(this.OptionsMonitor.CurrentValue.Roles.Windows.CacheEnabled)
			{
				var cacheKey = await this.CreateCacheKeyAsync(claimsPrincipal);

				if(!this.Cache.TryGetValue(cacheKey, out ISet<string> roles))
				{
					lock(this.CacheLock)
					{
						if(!this.Cache.TryGetValue(cacheKey, out roles))
						{
							try
							{
								roles = this.GetUncachedRolesInternalAsync(claimsPrincipal).Result;
							}
							catch(Exception exception)
							{
								this.Logger.LogErrorIfEnabled(exception, $"Could not get windows-roles for cache-key \"{cacheKey}\".");

								roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
							}

							this.Cache.Set(cacheKey, roles, this.OptionsMonitor.CurrentValue.Roles.Windows.CacheDuration);
						}
					}
				}

				return roles;
			}
			// ReSharper restore InvertIf

			return await this.GetUncachedRolesInternalAsync(claimsPrincipal);
		}

		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		protected internal virtual async Task<ISet<string>> GetUncachedRolesInternalAsync(ClaimsPrincipal claimsPrincipal)
		{
			if(claimsPrincipal == null)
				throw new ArgumentNullException(nameof(claimsPrincipal));

			if(claimsPrincipal is WindowsPrincipal windowsPrincipal)
				return await this.GetWindowsRoles(windowsPrincipal);

			var roles = await base.GetRolesInternalAsync(claimsPrincipal);

			var userPrincipalNameClaims = (await this.ClaimsPrincipalHelper.GetUserPrincipalNameClaimsAsync(claimsPrincipal, this.Logger)).ToArray();

			// ReSharper disable InvertIf
			if(userPrincipalNameClaims.Any())
			{
				foreach(var userPrincipalNameClaim in userPrincipalNameClaims)
				{
					var userPrincipalName = userPrincipalNameClaim.Value;

					try
					{
						foreach(var windowsRole in await this.GetWindowsRoles(userPrincipalName))
						{
							roles.Add(windowsRole);
						}
					}
					catch(Exception exception)
					{
						this.Logger.LogErrorIfEnabled(exception, $"Could not get windows-roles for user-principal-name \"{userPrincipalName}\".");
					}
				}
			}
			// ReSharper restore InvertIf

			return roles;
		}

		protected internal virtual async Task<ISet<string>> GetWindowsRoles(string userPrincipalName)
		{
			using(var windowsIdentity = new WindowsIdentity(userPrincipalName))
			{
				return await this.GetWindowsRoles(windowsIdentity);
			}
		}

		protected internal virtual async Task<ISet<string>> GetWindowsRoles(WindowsIdentity windowsIdentity)
		{
			if(windowsIdentity == null)
				throw new ArgumentNullException(nameof(windowsIdentity));

			// ReSharper disable AssignNullToNotNullAttribute
			var securityIdentifiers = windowsIdentity.Groups.Cast<SecurityIdentifier>();
			// ReSharper restore AssignNullToNotNullAttribute

			var options = this.OptionsMonitor.CurrentValue.Roles.Windows;

			if(!options.BuiltInRolesEnabled)
				securityIdentifiers = securityIdentifiers.Where(securityIdentifier => securityIdentifier.AccountDomainSid != null);

			var identityReferences = new IdentityReferenceCollection();

			foreach(var securityIdentifier in securityIdentifiers)
			{
				identityReferences.Add(securityIdentifier);
			}

			// ReSharper disable AssignNullToNotNullAttribute
			var windowsRoles = identityReferences.Translate(typeof(NTAccount)).Select(ntAccount => ntAccount.Value);
			// ReSharper restore AssignNullToNotNullAttribute

			if(!options.MachineRolesEnabled)
				windowsRoles = windowsRoles.Where(windowsRole => !windowsRole.StartsWith($"{Environment.MachineName}\\", StringComparison.OrdinalIgnoreCase));

			return await Task.FromResult(new SortedSet<string>(windowsRoles, StringComparer.OrdinalIgnoreCase));
		}

		protected internal virtual async Task<ISet<string>> GetWindowsRoles(WindowsPrincipal windowsPrincipal)
		{
			if(windowsPrincipal == null)
				throw new ArgumentNullException(nameof(windowsPrincipal));

			var windowsRoles = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

			foreach(var windowsIdentity in windowsPrincipal.Identities.OfType<WindowsIdentity>())
			{
				foreach(var windowsRole in await this.GetWindowsRoles(windowsIdentity))
				{
					windowsRoles.Add(windowsRole);
				}
			}

			return windowsRoles;
		}

		#endregion
	}
}