terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0, < 6.0"
    }

    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0.0, < 6.0"
    }
  }
}

locals {
  host_domain = coalesce(var.web_domain, var.local_domain)
}

data "google_client_config" "default" {
  provider = google-beta
}

# Prepare GKE ingress TLS certificate
resource "kubernetes_manifest" "managedcertificate_managed_cert" {
  manifest = {
    apiVersion = "networking.gke.io/v1"
    kind       = "ManagedCertificate"

    metadata = {
      name      = var.tls_certificate_name
      namespace = var.kubernetes_namespace
    }

    spec = {
      domains = [local.host_domain]
    }
  }
}

# Mastodon release on Kubernetes

# Mastodon does not yet publish its Helm chart in a chart repository
# See: https://github.com/mastodon/chart/issues/27
# See: https://github.com/mastodon/chart/pull/54
# Downloading as source as an interim solution

resource "helm_release" "mastodon" {
  name      = "mastodon"
  namespace = var.kubernetes_namespace
  chart     = "${path.module}/../charts/chart"

  create_namespace = true

  wait = false

  set {
    name  = "mastodon.createAdmin.enabled"
    value = var.create_admin
  }
  set {
    name  = "mastodon.createAdmin.username"
    value = var.create_admin_username
  }
  set {
    name  = "mastodon.createAdmin.email"
    value = var.create_admin_email
  }

  set {
    name  = "mastodon.local_domain"
    value = var.local_domain
  }

  set {
    name  = "mastodon.web_domain"
    value = var.web_domain
  }

  set {
    name  = "mastodon.persistence.assets.accessMode"
    value = "ReadWriteMany"
  }
  set {
    name  = "mastodon.persistence.system.accessMode"
    value = "ReadWriteMany"
  }

  set {
    name  = "mastodon.s3.enabled"
    value = true
  }
  set {
    name  = "mastodon.s3.access_key"
    value = var.dependencies.s3_access_key
  }
  set_sensitive {
    name  = "mastodon.s3.access_secret"
    value = var.dependencies.s3_access_secret
  }
  set {
    name  = "mastodon.s3.bucket"
    value = var.dependencies.gcs_name
  }
  set {
    name  = "mastodon.s3.endpoint"
    value = "https://storage.googleapis.com"
  }
  set {
    name  = "mastodon.s3.hostname"
    value = "storage.googleapis.com"
  }
  set {
    name  = "mastodon.s3.region"
    value = var.dependencies.gcs_region
  }

  set_sensitive {
    name  = "mastodon.secrets.secret_key_base"
    value = var.secret_key_base
  }
  set_sensitive {
    name  = "mastodon.secrets.otp_secret"
    value = var.otp_secret
  }
  set_sensitive {
    name  = "mastodon.secrets.vapid.private_key"
    value = var.vapid_private_key
  }
  set {
    name  = "mastodon.secrets.vapid.public_key"
    value = var.vapid_public_key
  }

  set_sensitive {
    name  = "mastodon.secrets.activeRecordEncryption.primaryKey"
    value = var.active_record_encryption_primary_key
  }

  set_sensitive {
    name  = "mastodon.secrets.activeRecordEncryption.deterministicKey"
    value = var.active_record_encryption_deterministic_key
  }

  set_sensitive {
    name  = "mastodon.secrets.activeRecordEncryption.keyDerivationSalt"
    value = var.active_record_encryption_key_derivation_salt
  }

  set {
    name  = "mastodon.smtp.auth_method"
    value = var.smtp_auth_method
  }
  set {
    name  = "mastodon.smtp.domain"
    value = coalesce(var.smtp_domain, var.local_domain)
  }
  set {
    name  = "mastodon.smtp.enable_starttls"
    value = var.smtp_enable_starttls
  }
  set {
    name  = "mastodon.smtp.from_address"
    value = var.smtp_from_address
  }
  set {
    name  = "mastodon.smtp.openssl_verify_mode"
    value = var.smtp_openssl_verify_mode
  }
  set {
    name  = "mastodon.smtp.port"
    value = var.smtp_port
  }
  set {
    name  = "mastodon.smtp.server"
    value = var.smtp_server
  }
  set_sensitive {
    name  = "mastodon.smtp.login"
    value = var.smtp_login
  }
  set_sensitive {
    name  = "mastodon.smtp.password"
    value = var.smtp_password
  }

  set {
    name  = "ingress.annotations.networking\\.gke\\.io/managed-certificates"
    value = var.tls_certificate_name
  }
  set {
    name  = "ingress.annotations.kubernetes\\.io/ingress\\.global-static-ip-name"
    value = var.dependencies.ingress_ipv4_name
  }
  set {
    name  = "ingress.hosts[0].host"
    value = local.host_domain
  }
  set {
    name  = "ingress.hosts[0].paths[0].path"
    value = "/"
  }
  set {
    name  = "ingress.tls"
    value = false
  }

  set {
    name  = "postgresql.enabled"
    value = false
  }
  set {
    name  = "postgresql.postgresqlHostname"
    value = var.dependencies.db_hostname
  }
  set {
    name  = "postgresql.postgresqlPort"
    value = 5432
  }
  set {
    name  = "postgresql.auth.database"
    value = var.dependencies.db_name
  }
  set {
    name  = "postgresql.auth.username"
    value = var.dependencies.db_user
  }
  set_sensitive {
    name  = "postgresql.auth.password"
    value = var.dependencies.db_pass
  }

  set {
    name  = "redis.enabled"
    value = false
  }
  set {
    name  = "redis.hostname"
    value = var.dependencies.redis_hostname
  }
  set {
    name  = "redis.port"
    value = var.dependencies.redis_port
  }
  set_sensitive {
    name  = "redis.auth.password"
    value = var.dependencies.redis_auth_string
  }

  set {
    name  = "elasticsearch.enabled"
    value = false
  }

  values = [
    yamlencode(var.node_selector != null ? { nodeSelector : var.node_selector } : {})
  ]
}

# Add ingress rule for redirecting http-to-https
resource "kubernetes_manifest" "frontendconfig_https_redirect" {
  manifest = {
    "apiVersion" = "networking.gke.io/v1beta1"
    "kind"       = "FrontendConfig"

    "metadata" = {
      "name"      = "https-redirect"
      "namespace" = var.kubernetes_namespace
    }

    "spec" = {
      "redirectToHttps" = {
        "enabled" = true
      }
    }
  }
}
