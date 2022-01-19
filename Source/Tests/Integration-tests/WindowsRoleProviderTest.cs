using System;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using HansKindberg.Web.Authorization;
using HansKindberg.Web.Authorization.Configuration;
using IntegrationTests.Helpers.Security.Principal.Extensions;
using IntegrationTests.Mocks.Logging;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace IntegrationTests
{
#if NET5_0_OR_GREATER
	[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
	[TestClass]
	public class WindowsRoleProviderTest
	{
		#region Methods

		protected internal virtual async Task<IMemoryCache> CreateMemoryCacheAsync()
		{
			return await Task.FromResult(Mock.Of<IMemoryCache>());
		}

		protected internal virtual async Task<IOptionsMonitor<ExtendedAuthorizationOptions>> CreateOptionsMonitorAsync(ExtendedAuthorizationOptions options = null)
		{
			return await Task.FromResult(Mock.Of<IOptionsMonitor<ExtendedAuthorizationOptions>>(optionsMonitor => optionsMonitor.CurrentValue == (options ?? new ExtendedAuthorizationOptions())));
		}

		protected internal virtual async Task<IPrincipal> CreatePrincipalAsync(string userPrincipalName, params string[] userPrincipalNameClaimTypes)
		{
			var claims = userPrincipalNameClaimTypes.Select(userPrincipalNameClaimType => new Claim(userPrincipalNameClaimType, userPrincipalName));

			return await Task.FromResult(new ClaimsPrincipal(new ClaimsIdentity(claims, "Integration-test")));
		}

		protected internal virtual async Task<WindowsRoleProvider> CreateWindowsRoleProviderAsync(LoggerFactoryMock loggerFactory, ExtendedAuthorizationOptions options = null)
		{
			return await Task.FromResult(new WindowsRoleProvider(await this.CreateMemoryCacheAsync(), new ClaimsPrincipalHelper(), loggerFactory, await this.CreateOptionsMonitorAsync(options)));
		}

		protected internal virtual async Task<string> GetLeadingDomainPartAsync(string userName)
		{
			userName ??= string.Empty;

			return await Task.FromResult(!userName.Contains('\\', StringComparison.OrdinalIgnoreCase) ? null : userName.Split('\\').First());
		}

		[TestMethod]
		public async Task GetRolesAsync_IfThereAreMultipelUserPrincipalNameClaims_ShouldLog()
		{
			using(var loggerFactory = new LoggerFactoryMock())
			{
				var claimsPrincipalHelper = new ClaimsPrincipalHelper();
				var windowsRoleProvider = new WindowsRoleProvider(await this.CreateMemoryCacheAsync(), claimsPrincipalHelper, loggerFactory, await this.CreateOptionsMonitorAsync());
				var principal = await this.CreatePrincipalAsync("Invalid-user-principal-name", claimsPrincipalHelper.UserPrincipalNameClaimTypes.ToArray());
				await windowsRoleProvider.GetRolesAsync(principal);
				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Warning, log.LogLevel);
				Assert.AreEqual("Multiple claims were found. The following claims were found: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn: Invalid-user-principal-name, upn: Invalid-user-principal-name", log.Message);
			}
		}

		[TestMethod]
		public async Task GetRolesAsync_IfTheUserPrincipalNameIsInvalid_ShouldLogAnError()
		{
			using(var loggerFactory = new LoggerFactoryMock())
			{
				var windowsRoleProvider = await this.CreateWindowsRoleProviderAsync(loggerFactory);
				var principal = await this.CreatePrincipalAsync("Invalid-user-principal-name", ClaimTypes.Upn);
				await windowsRoleProvider.GetRolesAsync(principal);
				var log = loggerFactory.Logs.First();
				Assert.AreEqual(LogLevel.Error, log.LogLevel);
				Assert.AreEqual("Could not get windows-roles for user-principal-name \"Invalid-user-principal-name\".", log.Message);
			}
		}

		[TestMethod]
		public async Task GetRolesAsync_IfTheUserPrincipalNameIsInvalid_ShouldReturnNoRoles()
		{
			using(var loggerFactory = new LoggerFactoryMock())
			{
				var claimsPrincipalHelper = new ClaimsPrincipalHelper();
				var windowsRoleProvider = new WindowsRoleProvider(await this.CreateMemoryCacheAsync(), claimsPrincipalHelper, loggerFactory, await this.CreateOptionsMonitorAsync());
				var principal = await this.CreatePrincipalAsync("Invalid-user-principal-name", claimsPrincipalHelper.UserPrincipalNameClaimTypes.ToArray());
				var roles = (await windowsRoleProvider.GetRolesAsync(principal)).ToArray();
				Assert.IsFalse(roles.Any());
			}
		}

		[TestMethod]
		public async Task GetRolesAsync_ShouldReturnCorrectRoles()
		{
			var currentWindowsIdentity = WindowsIdentity.GetCurrent();
			var domain = await GetLeadingDomainPartAsync(currentWindowsIdentity.Name);
			var userPrincipalName = UserPrincipal.Current.UserPrincipalName;

			using(var createdWindowsIdentity = new WindowsIdentity(userPrincipalName))
			{
				var currentWindowsGroups = currentWindowsIdentity.Groups;
				var createdWindowsGroups = createdWindowsIdentity.Groups;
				var principal = await this.CreatePrincipalAsync(userPrincipalName, ClaimTypes.Upn);
				var currentWindowsPrincipal = new WindowsPrincipal(currentWindowsIdentity);

				await this.GetRolesAsyncTest(false, domain, "Error for first test.", false, principal, createdWindowsGroups);
				await this.GetRolesAsyncTest(true, domain, "Error for second test.", false, principal, createdWindowsGroups);
				await this.GetRolesAsyncTest(false, domain, "Error for third test.", true, principal, createdWindowsGroups);
				await this.GetRolesAsyncTest(true, domain, "Error for fourth test.", true, principal, createdWindowsGroups);

				await this.GetRolesAsyncTest(false, domain, "Error for fifth test.", false, currentWindowsPrincipal, currentWindowsGroups);
				await this.GetRolesAsyncTest(true, domain, "Error for sixth test.", false, currentWindowsPrincipal, currentWindowsGroups);
				await this.GetRolesAsyncTest(false, domain, "Error for seventh test.", true, currentWindowsPrincipal, currentWindowsGroups);
				await this.GetRolesAsyncTest(true, domain, "Error for eighth test.", true, currentWindowsPrincipal, currentWindowsGroups);
			}
		}

		protected internal virtual async Task GetRolesAsyncTest(bool builtInRolesEnabled, string domain, string errorMessage, bool machineRolesEnabled, IPrincipal principal, IdentityReferenceCollection windowsGroups)
		{
			if(domain == null)
				throw new ArgumentNullException(nameof(domain));

			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			if(windowsGroups == null)
				throw new ArgumentNullException(nameof(windowsGroups));

			var options = new ExtendedAuthorizationOptions
			{
				Roles =
				{
					Windows =
					{
						BuiltInRolesEnabled = builtInRolesEnabled,
						MachineRolesEnabled = machineRolesEnabled
					}
				}
			};

			var expectedRoles = windowsGroups.AsRoles(options.Roles.Windows);

			using(var loggerFactory = new LoggerFactoryMock())
			{
				var windowsRoleProvider = await this.CreateWindowsRoleProviderAsync(loggerFactory, options);
				var roles = (await windowsRoleProvider.GetRolesAsync(principal)).ToArray();
				Assert.AreEqual(expectedRoles.Count, roles.Length, errorMessage);

				for(var i = 0; i < roles.Length; i++)
				{
					var role = roles[i];

					// ReSharper disable All
					if(!builtInRolesEnabled && !machineRolesEnabled)
						Assert.IsTrue(role.StartsWith($"{domain}\\", StringComparison.OrdinalIgnoreCase), errorMessage);
					else if(builtInRolesEnabled && !machineRolesEnabled)
						Assert.IsFalse(role.StartsWith(Environment.MachineName, StringComparison.OrdinalIgnoreCase), errorMessage);
					else if(!builtInRolesEnabled && machineRolesEnabled)
						Assert.IsTrue(role.StartsWith($"{domain}\\", StringComparison.OrdinalIgnoreCase) || role.StartsWith(Environment.MachineName, StringComparison.OrdinalIgnoreCase), errorMessage);
					// ReSharper restore All

					Assert.AreEqual(expectedRoles.ElementAt(i), role, errorMessage);
				}
			}
		}

		#endregion
	}
}