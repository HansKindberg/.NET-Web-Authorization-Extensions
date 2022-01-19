using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using HansKindberg.Web.Authorization;
using HansKindberg.Web.Authorization.DependencyInjection.Extensions;
using IntegrationTests.Helpers.Security.Principal.Extensions;
using IntegrationTests.Mocks.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IntegrationTests
{
	[TestClass]
	public class AuthorizationResolverTest
	{
		#region Fields

		private static readonly string _resourcesDirectoryPath = Path.Combine(Global.ProjectDirectoryPath, _relativeResourcesDirectoryPath);
		private static readonly string _appSettingsDefaultJsonFileName = $"{_appSettingsJsonFileName}.Default";
		private static readonly string _appSettingsDefaultJsonFilePath = Path.Combine(_resourcesDirectoryPath, $"{_appSettingsDefaultJsonFileName}.json");
		private const string _appSettingsJsonFileName = "AppSettings";
		private static readonly string _appSettingsJsonFilePath = Path.Combine(_resourcesDirectoryPath, $"{_appSettingsJsonFileName}.json");
		private const string _relativeResourcesDirectoryPath = @"Resources\AuthorizationResolver";

		#endregion

		#region Methods

		protected internal virtual async Task<AuthorizationResolver> CreateAuthorizationResolverAsync()
		{
			return (AuthorizationResolver)(await this.CreateServiceProviderAsync()).GetRequiredService<IAuthorizationResolver>();
		}

		protected internal virtual async Task<AuthorizationResolver> CreateAuthorizationResolverAsync(string appSettingsFileName)
		{
			return (AuthorizationResolver)(await this.CreateServiceProviderAsync(appSettingsFileName)).GetRequiredService<IAuthorizationResolver>();
		}

		protected internal virtual async Task<IPrincipal> CreatePrincipalAsync(string userIdentifier)
		{
			var claims = new[] { new Claim(ClaimTypes.NameIdentifier, userIdentifier) };

			return await Task.FromResult(new ClaimsPrincipal(new ClaimsIdentity(claims, "Integration-test")));
		}

		protected internal virtual async Task<IServiceProvider> CreateServiceProviderAsync()
		{
			return await this.CreateServiceProviderAsync(_appSettingsJsonFileName);
		}

		[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope")]
		protected internal virtual async Task<IServiceProvider> CreateServiceProviderAsync(string appSettingsFileName)
		{
			var configurationBuilder = new ConfigurationBuilder();
			configurationBuilder.AddJsonFile($"{appSettingsFileName}.json", false, true);
			configurationBuilder.SetFileProvider(new PhysicalFileProvider(_resourcesDirectoryPath));
			var configuration = configurationBuilder.Build();

			var services = new ServiceCollection();

			services.AddExtendedAuthorization(configuration);
			services.AddSingleton<IConfiguration>(configuration);
			services.AddSingleton<ILoggerFactory, LoggerFactoryMock>();

			return await Task.FromResult(services.BuildServiceProvider());
		}

		protected internal static async Task EnsureAppSettingsJsonFileIsDeleted()
		{
			await Task.CompletedTask;

			if(File.Exists(_appSettingsJsonFilePath))
				File.Delete(_appSettingsJsonFilePath);
		}

		[TestMethod]
		public async Task GetPolicyAsync_Test()
		{
			var authorizationResolver = await this.CreateAuthorizationResolverAsync();

			var principal = await this.CreatePrincipalAsync("1");
			var policy = await authorizationResolver.GetPolicyAsync(principal);
			Assert.AreEqual(3, policy.Permissions.Count());
			Assert.AreEqual(4, policy.Roles.Count());

			principal = await this.CreatePrincipalAsync("2");
			policy = await authorizationResolver.GetPolicyAsync(principal);
			Assert.AreEqual(3, policy.Permissions.Count());
			Assert.AreEqual(3, policy.Roles.Count());

			principal = await this.CreatePrincipalAsync("3");
			policy = await authorizationResolver.GetPolicyAsync(principal);
			Assert.AreEqual(3, policy.Permissions.Count());
			Assert.AreEqual(2, policy.Roles.Count());

			principal = await this.CreatePrincipalAsync("4");
			policy = await authorizationResolver.GetPolicyAsync(principal);
			Assert.AreEqual(3, policy.Permissions.Count());
			Assert.AreEqual(1, policy.Roles.Count());

			principal = await this.CreatePrincipalAsync("5");
			policy = await authorizationResolver.GetPolicyAsync(principal);
			Assert.AreEqual(0, policy.Permissions.Count());
			Assert.AreEqual(0, policy.Roles.Count());
		}

		[TestMethod]
		public async Task GetPolicyAsync_UpdateConfiguration_Test()
		{
			await Task.CompletedTask;

			var authorizationResolver = await this.CreateAuthorizationResolverAsync();

			Assert.AreEqual(1, authorizationResolver.PermissionProviders.Count());
			Assert.IsTrue(authorizationResolver.PermissionProviders.First() is ConfigurationPermissionProvider);
			Assert.AreEqual(2, authorizationResolver.RoleProviders.Count());
			Assert.IsTrue(authorizationResolver.RoleProviders.First() is ConfigurationRoleProvider);
			Assert.IsTrue(authorizationResolver.RoleProviders.ElementAt(1) is WindowsRoleProvider);
			var principal = await this.CreatePrincipalAsync("1");
			var policy = await authorizationResolver.GetPolicyAsync(principal);
			Assert.AreEqual(3, policy.Permissions.Count());
			Assert.AreEqual(4, policy.Roles.Count());

			var update1Content = await File.ReadAllTextAsync(Path.Combine(_resourcesDirectoryPath, "Update-1.json"));
			await File.WriteAllTextAsync(_appSettingsJsonFilePath, update1Content);

			Thread.Sleep(1000);

			Assert.AreEqual(1, authorizationResolver.PermissionProviders.Count());
			Assert.IsTrue(authorizationResolver.PermissionProviders.First() is ConfigurationPermissionProvider);
			Assert.AreEqual(1, authorizationResolver.RoleProviders.Count());
			Assert.IsTrue(authorizationResolver.RoleProviders.First() is ConfigurationRoleProvider);
			principal = await this.CreatePrincipalAsync("1");
			policy = await authorizationResolver.GetPolicyAsync(principal);
			Assert.AreEqual(1, policy.Permissions.Count());
			Assert.AreEqual(1, policy.Roles.Count());
		}

#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
		[TestMethod]
		public async Task GetPolicyAsync_WindowsPrincipal_Test()
		{
			var windowsIdentity = WindowsIdentity.GetCurrent();

			var expectedRoles = windowsIdentity.GetRoles();

			var authorizationResolver = await this.CreateAuthorizationResolverAsync();

			var principal = new WindowsPrincipal(windowsIdentity);
			var policy = await authorizationResolver.GetPolicyAsync(principal);
			Assert.AreEqual(0, policy.Permissions.Count());
			Assert.AreEqual(expectedRoles.Count, policy.Roles.Count());

			for(var i = 0; i < expectedRoles.Count; i++)
			{
				Assert.AreEqual(expectedRoles.ElementAt(i), policy.Roles.ElementAt(i));
			}
		}

		[TestCleanup]
		public async Task TestCleanup()
		{
			await EnsureAppSettingsJsonFileIsDeleted();
		}

		[TestInitialize]
		public async Task TestInitialize()
		{
			await EnsureAppSettingsJsonFileIsDeleted();

			File.Copy(_appSettingsDefaultJsonFilePath, _appSettingsJsonFilePath);
		}

		#endregion
	}
}