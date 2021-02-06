using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using HansKindberg.Web.Authorization.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.Logging.Extensions;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public class AuthorizationResolver : IAuthorizationResolver
	{
		#region Fields

		private static readonly IEnumerable<Type> _defaultPermissionProviderTypes = new[] {typeof(ConfigurationPermissionProvider)};
		private static readonly IEnumerable<Type> _defaultRoleProviderTypes = new[] {typeof(ConfigurationRoleProvider)};
		private IEnumerable<IPermissionProvider> _permissionProviders;
		private IEnumerable<IRoleProvider> _roleProviders;

		#endregion

		#region Constructors

		public AuthorizationResolver(ILoggerFactory loggerFactory, IOptionsMonitor<ExtendedAuthorizationOptions> optionsMonitor, IServiceProvider serviceProvider)
		{
			this.Logger = (loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory))).CreateLogger(this.GetType());
			this.OptionsMonitor = optionsMonitor ?? throw new ArgumentNullException(nameof(optionsMonitor));
			this.ServiceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));

			this.OptionsChangeListener = optionsMonitor.OnChange(this.OnOptionsChange);
		}

		#endregion

		#region Properties

		protected internal virtual IEnumerable<Type> DefaultPermissionProviderTypes => _defaultPermissionProviderTypes;
		protected internal virtual IEnumerable<Type> DefaultRoleProviderTypes => _defaultRoleProviderTypes;
		protected internal virtual ILogger Logger { get; }
		protected internal virtual IDisposable OptionsChangeListener { get; }
		protected internal virtual IOptionsMonitor<ExtendedAuthorizationOptions> OptionsMonitor { get; }

		protected internal virtual IEnumerable<IPermissionProvider> PermissionProviders
		{
			get
			{
				// ReSharper disable InvertIf
				if(this._permissionProviders == null)
				{
					lock(this.PermissionProvidersLock)
					{
						if(this._permissionProviders == null)
						{
							try
							{
								this._permissionProviders = this.CreateCollection<IPermissionProvider>(this.DefaultPermissionProviderTypes, this.OptionsMonitor.CurrentValue.Permissions.Providers);
							}
							catch(Exception exception)
							{
								const string message = "Could not get permission-providers.";

								this.Logger.LogErrorIfEnabled(exception, message);

								if(this.OptionsMonitor.CurrentValue.ThrowConfigurationExceptions)
									throw new InvalidOperationException(message, exception);
							}
						}
					}
				}
				// ReSharper restore InvertIf

				return this._permissionProviders;
			}
		}

		protected internal virtual object PermissionProvidersLock { get; } = new object();

		protected internal virtual IEnumerable<IRoleProvider> RoleProviders
		{
			get
			{
				// ReSharper disable InvertIf
				if(this._roleProviders == null)
				{
					lock(this.RoleProvidersLock)
					{
						if(this._roleProviders == null)
						{
							try
							{
								this._roleProviders = this.CreateCollection<IRoleProvider>(this.DefaultRoleProviderTypes, this.OptionsMonitor.CurrentValue.Roles.Providers);
							}
							catch(Exception exception)
							{
								const string message = "Could not get role-providers.";

								this.Logger.LogErrorIfEnabled(exception, message);

								if(this.OptionsMonitor.CurrentValue.ThrowConfigurationExceptions)
									throw new InvalidOperationException(message, exception);
							}
						}
					}
				}
				// ReSharper restore InvertIf

				return this._roleProviders;
			}
		}

		protected internal virtual object RoleProvidersLock { get; } = new object();
		protected internal virtual IServiceProvider ServiceProvider { get; }

		#endregion

		#region Methods

		protected internal virtual IEnumerable<T> CreateCollection<T>(IEnumerable<Type> defaultTypes, IEnumerable<string> typeValues)
		{
			if(defaultTypes == null)
				throw new ArgumentNullException(nameof(defaultTypes));

			if(typeValues == null)
				throw new ArgumentNullException(nameof(typeValues));

			var collection = new List<T>();

			foreach(var type in this.GetTypes(defaultTypes, typeValues))
			{
				try
				{
					if(!typeof(T).IsAssignableFrom(type))
						throw new InvalidOperationException($"Type \"{type}\" does not implement/inherit \"{typeof(T)}\".");

					var item = (T)this.ServiceProvider.GetRequiredService(type);

					collection.Add(item);
				}
				catch(Exception exception)
				{
					var message = $"Could not add item of type \"{type}\" to the collection.";

					this.Logger.LogErrorIfEnabled(exception, message);

					if(this.OptionsMonitor.CurrentValue.ThrowConfigurationExceptions)
						throw new InvalidOperationException(message, exception);
				}
			}

			return collection;
		}

		public virtual async Task<IPolicy> GetPolicyAsync(IPrincipal principal)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			var policy = new Policy();

			foreach(var roleProvider in this.RoleProviders)
			{
				foreach(var role in await roleProvider.GetRolesAsync(principal))
				{
					policy.Roles.Add(role);
				}
			}

			foreach(var permissionProvider in this.PermissionProviders)
			{
				foreach(var permission in await permissionProvider.GetPermissionsAsync(principal, policy.Roles))
				{
					policy.Permissions.Add(permission);
				}
			}

			return await Task.FromResult(policy);
		}

		protected internal virtual ISet<Type> GetTypes(IEnumerable<Type> defaultTypes, IEnumerable<string> typeValues)
		{
			if(defaultTypes == null)
				throw new ArgumentNullException(nameof(defaultTypes));

			if(typeValues == null)
				throw new ArgumentNullException(nameof(typeValues));

			var types = new HashSet<Type>(defaultTypes);

			foreach(var typeValue in typeValues)
			{
				try
				{
					var type = Type.GetType(typeValue, true);

					types.Add(type);
				}
				catch(Exception exception)
				{
					var message = $"Could not get a type from value \"{typeValue}\".";

					this.Logger.LogErrorIfEnabled(exception, message);

					if(this.OptionsMonitor.CurrentValue.ThrowConfigurationExceptions)
						throw new InvalidOperationException(message, exception);
				}
			}

			return types;
		}

		public virtual async Task<bool> HasPermissionAsync(string permission, IPrincipal principal)
		{
			var policy = await this.GetPolicyAsync(principal);

			return policy.Permissions.Contains(permission);
		}

		public virtual async Task<bool> IsInRoleAsync(IPrincipal principal, string role)
		{
			var policy = await this.GetPolicyAsync(principal);

			return policy.Roles.Contains(role);
		}

		protected internal virtual void OnOptionsChange(ExtendedAuthorizationOptions options, string name)
		{
			this.Logger.LogDebugIfEnabled($"Options-change in \"{this.GetType()}\", options of type \"{options?.GetType()}\" and name {(name != null ? $"\"{name}\"" : "null")}. Setting permission-providers and role-providers to null.");

			lock(this.PermissionProvidersLock)
			{
				this._permissionProviders = null;
			}

			lock(this.RoleProvidersLock)
			{
				this._roleProviders = null;
			}
		}

		#endregion

		#region Other members

		~AuthorizationResolver()
		{
			this.OptionsChangeListener?.Dispose();
		}

		#endregion
	}
}