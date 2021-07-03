using System;
using System.IO;
using Application.Models;
using Application.Models.Web.Authentication;
using HansKindberg.Web.Authorization.Builder.Extentsions;
using HansKindberg.Web.Authorization.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RegionOrebroLan;
using RegionOrebroLan.Caching.Distributed.Builder.Extensions;
using RegionOrebroLan.Caching.Distributed.DependencyInjection.Extensions;
using RegionOrebroLan.DataProtection.Builder.Extensions;
using RegionOrebroLan.DataProtection.DependencyInjection.Extensions;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Extensions;
using RegionOrebroLan.Security.Cryptography;
using RegionOrebroLan.Web.Authentication.Cookies.DependencyInjection.Extensions;

namespace Application
{
	public class Startup
	{
		#region Constructors

		public Startup(IConfiguration configuration, IWebHostEnvironment hostEnvironment)
		{
			this.Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
			this.HostEnvironment = hostEnvironment ?? throw new ArgumentNullException(nameof(hostEnvironment));
		}

		#endregion

		#region Properties

		protected internal virtual IConfiguration Configuration { get; }
		protected internal virtual IWebHostEnvironment HostEnvironment { get; }

		#endregion

		#region Methods

		public virtual void Configure(IApplicationBuilder applicationBuilder)
		{
			if(applicationBuilder == null)
				throw new ArgumentNullException(nameof(applicationBuilder));

			applicationBuilder
				.UseDeveloperExceptionPage()
				.UseDataProtection()
				.UseDistributedCache()
				.UseStaticFiles()
				.UseRouting()
				.UseAuthentication()
				.UseExtendedAuthorization()
				.UseEndpoints(endpoints =>
				{
					endpoints.MapDefaultControllerRoute();
				});
		}

		public virtual void ConfigureServices(IServiceCollection services)
		{
			if(services == null)
				throw new ArgumentNullException(nameof(services));

			AppDomain.CurrentDomain.SetDataDirectory(Path.Combine(this.HostEnvironment.ContentRootPath, "Data"));

			var instanceFactory = new InstanceFactory();
			services.AddDataProtection(this.CreateCertificateResolver(), this.Configuration, this.HostEnvironment, instanceFactory);
			services.AddDistributedCache(this.Configuration, this.HostEnvironment, instanceFactory);
			services.AddTicketStore(this.Configuration, this.HostEnvironment, instanceFactory);

			services.AddAuthentication(AuthenticationSchemes.Cookie)
				.AddCookie(AuthenticationSchemes.Cookie, options =>
				{
					options.AccessDeniedPath = "/Account/AccessDenied";
					options.LoginPath = "/Account/SignIn";
					options.LogoutPath = "/Account/SignOut";
				})
				.AddCookie(AuthenticationSchemes.Intermediate);

			services.AddControllersWithViews();

			services.AddExtendedAuthorization(this.Configuration);

			services.AddScoped<IFacade, Facade>();

			services.Configure<IISOptions>(options =>
			{
				options.AuthenticationDisplayName = AuthenticationSchemes.Windows;
				options.AutomaticAuthentication = false;
			});

			services.Configure<IISServerOptions>(options =>
			{
				options.AuthenticationDisplayName = AuthenticationSchemes.Windows;
				options.AutomaticAuthentication = false;
			});
		}

		protected internal virtual ICertificateResolver CreateCertificateResolver()
		{
			var applicationDomain = new ApplicationHost(AppDomain.CurrentDomain, this.HostEnvironment);
			var fileCertificateResolver = new FileCertificateResolver(applicationDomain);
			var storeCertificateResolver = new StoreCertificateResolver();

			return new CertificateResolver(fileCertificateResolver, storeCertificateResolver);
		}

		#endregion
	}
}