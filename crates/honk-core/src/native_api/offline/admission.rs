use super::*;

impl CapturedConfig {
    /// Drops the captured asset bytes that [`Self::with_geo`] replaces, so a
    /// geodata update does not hold the loaded files beside the downloads.
    pub(crate) fn release_geo(&mut self) {
        self.geo = GeoSourceSet::load(&GeoRequirements::default());
    }

    pub(crate) fn with_geo(mut self, geo: GeoSourceSet) -> Result<Self, DetailedConfigError> {
        let requirements = GeoRequirements::for_traffic(&self.config.routing.rules)
            .union(&DnsRouter::geo_requirements(&self.config.dns));
        let source = &self.sources[0].source;
        self.dependencies.retain(|dependency| !dependency.asset);
        self.dependencies.extend(
            geo_dependencies(&geo, &requirements)
                .map_err(|cause| dependency_error(source, "routing", cause))?,
        );
        self.dependencies.sort_unstable();
        self.geo = geo;
        self.retain_geo = true;
        Ok(self)
    }

    pub(crate) fn validate(self) -> Result<ValidatedConfig, DetailedConfigError> {
        let Self {
            config,
            sources,
            dependencies,
            geo,
            retain_geo,
            hosts,
            ech_paths,
            dependency_root,
        } = self;
        let source = &sources[0].source;
        let dns_requirements = DnsRouter::geo_requirements(&config.dns);
        let requirements =
            GeoRequirements::for_traffic(&config.routing.rules).union(&dns_requirements);
        geo.validate(&requirements)
            .map_err(|cause| dependency_error(source, "routing", cause))?;
        let hosts = hosts
            .parse()
            .map_err(|cause| dependency_error(source, "dns", cause))?;
        let router = Router::from_config_with_geo_sources(&config.routing, &geo).map_err(|_| {
            error(
                source,
                "routing",
                "invalid-routing-config",
                "routing configuration cannot be compiled",
            )
        })?;
        ControlPlane::compile_routing_plan(&config, &router).map_err(|_| {
            error(
                source,
                "routing",
                "invalid-routing-config",
                "routing configuration cannot be compiled",
            )
        })?;
        DnsRouter::new_with_geo_sources(&config.dns, &geo).map_err(|_| {
            error(
                source,
                "dns",
                "invalid-dns-config",
                "DNS routing configuration cannot be compiled",
            )
        })?;
        PolicyId::from_config_with_artifacts(
            &config.dns,
            &hosts.fingerprint(),
            &geo.fingerprint_for(&dns_requirements),
        )
        .map_err(|_| {
            error(
                source,
                "dns",
                "invalid-dns-config",
                "DNS policy configuration is invalid",
            )
        })?;
        Ok(ValidatedConfig {
            config,
            sources,
            dependencies,
            geo_sources: retain_geo.then_some(geo),
            ech_paths,
            dependency_root,
        })
    }
}

impl ValidatedConfig {
    pub(crate) fn recapture_dependencies(
        &self,
        active: &Config,
        data_dir: &Path,
        limits: SourceLimits,
        deferred: &[honk_config::subscription::Subscription],
    ) -> io::Result<Vec<DependencySnapshot>> {
        let mut capture = Capture::new(
            &self.sources,
            self.dependency_root.as_deref(),
            active,
            data_dir,
            limits,
            &[],
        )?;
        if self
            .config
            .subscriptions
            .iter()
            .any(|subscription| subscription.enabled)
        {
            let store = StoredBodies::open(data_dir)?;
            for (index, subscription) in self
                .config
                .subscriptions
                .iter()
                .enumerate()
                .filter(|(_, subscription)| subscription.enabled)
            {
                if deferred.iter().any(|owner| {
                    crate::subscription::same_subscription_source_spec(owner, subscription)
                }) {
                    continue;
                }
                if let Some(body) = store
                    .as_ref()
                    .map(|store| store.find(subscription))
                    .transpose()?
                    .flatten()
                {
                    let (label, length) = (body.label.clone(), body.length);
                    capture.stored(label, length, DependencyReader::Subscription(index), || {
                        body.read()
                    })?;
                }
            }
        }
        let requirements = GeoRequirements::for_traffic(&self.config.routing.rules)
            .union(&DnsRouter::geo_requirements(&self.config.dns));
        let mut dependencies = if let Some(geo) = &self.geo_sources {
            geo_dependencies(geo, &requirements)?
        } else {
            GeoSourceSet::capture_for_admission(&requirements, data_dir, |kind, path| {
                capture.path(path, true, DependencyReader::Geo(kind))
            })?;
            Vec::new()
        };
        for (index, path) in self.config.dns.hosts.iter().enumerate() {
            capture.text(path, DependencyReader::Hosts(index, path.clone()))?;
        }
        for (index, path) in self.ech_paths.iter().enumerate() {
            capture.text(path, DependencyReader::Ech(index, path.clone()))?;
        }
        dependencies.extend(capture.files.into_iter().map(|(snapshot, _)| snapshot));
        dependencies.sort_unstable();
        Ok(dependencies)
    }
}
