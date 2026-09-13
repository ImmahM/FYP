--
-- PostgreSQL database dump
--

-- Dumped from database version 12.22
-- Dumped by pg_dump version 12.22

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: archerysettings_arachnisettingsdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.archerysettings_arachnisettingsdb (
    id integer NOT NULL,
    setting_id uuid,
    arachni_url text,
    arachni_port text,
    arachni_user text,
    arachni_pass text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.archerysettings_arachnisettingsdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_arachnisettingsdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.archerysettings_arachnisettingsdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.archerysettings_arachnisettingsdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_arachnisettingsdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.archerysettings_arachnisettingsdb_id_seq OWNED BY public.archerysettings_arachnisettingsdb.id;


--
-- Name: archerysettings_burpsettingdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.archerysettings_burpsettingdb (
    id integer NOT NULL,
    setting_id uuid,
    burp_url text,
    burp_port text,
    burp_api_key text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.archerysettings_burpsettingdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_burpsettingdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.archerysettings_burpsettingdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.archerysettings_burpsettingdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_burpsettingdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.archerysettings_burpsettingdb_id_seq OWNED BY public.archerysettings_burpsettingdb.id;


--
-- Name: archerysettings_emaildb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.archerysettings_emaildb (
    id integer NOT NULL,
    setting_id uuid,
    subject text,
    message text,
    recipient_list text NOT NULL,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer,
    smtp_host character varying(255),
    smtp_port integer,
    smtp_use_tls boolean NOT NULL,
    smtp_user character varying(255),
    smtp_password text,
    sender_email character varying(254),
    CONSTRAINT archerysettings_emaildb_smtp_port_check CHECK ((smtp_port >= 0))
);


ALTER TABLE public.archerysettings_emaildb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_emaildb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.archerysettings_emaildb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.archerysettings_emaildb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_emaildb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.archerysettings_emaildb_id_seq OWNED BY public.archerysettings_emaildb.id;


--
-- Name: archerysettings_niktosettingdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.archerysettings_niktosettingdb (
    id integer NOT NULL,
    setting_id uuid,
    binary_path text,
    enabled boolean NOT NULL,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    created_by_id integer,
    updated_by_id integer
);


ALTER TABLE public.archerysettings_niktosettingdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_niktosettingdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.archerysettings_niktosettingdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.archerysettings_niktosettingdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_niktosettingdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.archerysettings_niktosettingdb_id_seq OWNED BY public.archerysettings_niktosettingdb.id;


--
-- Name: archerysettings_nmapsettingdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.archerysettings_nmapsettingdb (
    id integer NOT NULL,
    setting_id uuid,
    binary_path text,
    enabled boolean NOT NULL,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    created_by_id integer,
    updated_by_id integer
);


ALTER TABLE public.archerysettings_nmapsettingdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_nmapsettingdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.archerysettings_nmapsettingdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.archerysettings_nmapsettingdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_nmapsettingdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.archerysettings_nmapsettingdb_id_seq OWNED BY public.archerysettings_nmapsettingdb.id;


--
-- Name: archerysettings_nmapvulnerssettingdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.archerysettings_nmapvulnerssettingdb (
    id integer NOT NULL,
    setting_id uuid,
    enabled boolean NOT NULL,
    version boolean NOT NULL,
    online boolean NOT NULL,
    timing integer NOT NULL,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.archerysettings_nmapvulnerssettingdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_nmapvulnerssettingdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.archerysettings_nmapvulnerssettingdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.archerysettings_nmapvulnerssettingdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_nmapvulnerssettingdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.archerysettings_nmapvulnerssettingdb_id_seq OWNED BY public.archerysettings_nmapvulnerssettingdb.id;


--
-- Name: archerysettings_openvassettingdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.archerysettings_openvassettingdb (
    id integer NOT NULL,
    setting_id uuid,
    host text,
    port integer NOT NULL,
    enabled boolean NOT NULL,
    "user" text,
    password text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.archerysettings_openvassettingdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_openvassettingdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.archerysettings_openvassettingdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.archerysettings_openvassettingdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_openvassettingdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.archerysettings_openvassettingdb_id_seq OWNED BY public.archerysettings_openvassettingdb.id;


--
-- Name: archerysettings_settingsdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.archerysettings_settingsdb (
    id integer NOT NULL,
    setting_id uuid,
    setting_name text,
    setting_scanner text,
    setting_status boolean,
    created_time timestamp with time zone NOT NULL,
    created_by_id integer,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.archerysettings_settingsdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_settingsdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.archerysettings_settingsdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.archerysettings_settingsdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_settingsdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.archerysettings_settingsdb_id_seq OWNED BY public.archerysettings_settingsdb.id;


--
-- Name: archerysettings_zapsettingsdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.archerysettings_zapsettingsdb (
    id integer NOT NULL,
    setting_id uuid,
    zap_url text NOT NULL,
    zap_api text NOT NULL,
    zap_port integer NOT NULL,
    enabled boolean NOT NULL,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer,
    auth_method character varying(20) NOT NULL,
    logged_in_regex text NOT NULL,
    login_url text NOT NULL,
    password_field text NOT NULL,
    password_value text NOT NULL,
    username_field text NOT NULL,
    username_value text NOT NULL
);


ALTER TABLE public.archerysettings_zapsettingsdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_zapsettingsdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.archerysettings_zapsettingsdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.archerysettings_zapsettingsdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: archerysettings_zapsettingsdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.archerysettings_zapsettingsdb_id_seq OWNED BY public.archerysettings_zapsettingsdb.id;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.audit_log (
    id uuid NOT NULL,
    action character varying(30) NOT NULL,
    resource_type character varying(30) NOT NULL,
    resource_id character varying(100) NOT NULL,
    details jsonb NOT NULL,
    ip_address inet,
    user_agent text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    user_id integer
);


ALTER TABLE public.audit_log OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: auth_group; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.auth_group (
    id integer NOT NULL,
    name character varying(150) NOT NULL
);


ALTER TABLE public.auth_group OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: auth_group_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.auth_group_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_group_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: auth_group_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.auth_group_id_seq OWNED BY public.auth_group.id;


--
-- Name: auth_group_permissions; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.auth_group_permissions (
    id integer NOT NULL,
    group_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.auth_group_permissions OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: auth_group_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.auth_group_permissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_group_permissions_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: auth_group_permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.auth_group_permissions_id_seq OWNED BY public.auth_group_permissions.id;


--
-- Name: auth_permission; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.auth_permission (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    content_type_id integer NOT NULL,
    codename character varying(100) NOT NULL
);


ALTER TABLE public.auth_permission OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: auth_permission_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.auth_permission_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_permission_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: auth_permission_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.auth_permission_id_seq OWNED BY public.auth_permission.id;


--
-- Name: authtoken_token; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.authtoken_token (
    key character varying(40) NOT NULL,
    created timestamp with time zone NOT NULL,
    user_id integer NOT NULL
);


ALTER TABLE public.authtoken_token OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: cicd_scannercommand; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.cicd_scannercommand (
    id integer NOT NULL,
    scanner character varying(50) NOT NULL,
    command text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.cicd_scannercommand OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: cicd_scannercommand_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.cicd_scannercommand_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.cicd_scannercommand_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: cicd_scannercommand_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.cicd_scannercommand_id_seq OWNED BY public.cicd_scannercommand.id;


--
-- Name: cicddb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.cicddb (
    id integer NOT NULL,
    cicd_id uuid NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    threshold text,
    date_time timestamp with time zone,
    threshold_count integer,
    build_id text,
    commit_hash text,
    branch_tag text,
    repo character varying(200),
    scm_server text,
    build_server text,
    total_vul integer,
    critical_vul integer,
    high_vul integer,
    medium_vul integer,
    low_vul integer,
    info_vul integer,
    project_id integer,
    command text,
    scanner text,
    target text,
    target_name text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.cicddb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: cicddb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.cicddb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.cicddb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: cicddb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.cicddb_id_seq OWNED BY public.cicddb.id;


--
-- Name: cloudscansdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.cloudscansdb (
    id integer NOT NULL,
    "cloudAccountId" text,
    scan_id uuid NOT NULL,
    rescan_id text,
    scan_date text NOT NULL,
    scan_status text NOT NULL,
    total_vul integer,
    critical_vul integer,
    high_vul integer,
    medium_vul integer,
    low_vul integer,
    info_vul integer,
    date_time timestamp with time zone,
    rescan text,
    total_dup text,
    scanner character varying(256),
    updated_time timestamp with time zone,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.cloudscansdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: cloudscansdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.cloudscansdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.cloudscansdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: cloudscansdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.cloudscansdb_id_seq OWNED BY public.cloudscansdb.id;


--
-- Name: cloudscansresultsdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.cloudscansresultsdb (
    id integer NOT NULL,
    scan_id uuid NOT NULL,
    rescan_id text,
    date_time timestamp with time zone,
    vuln_id uuid NOT NULL,
    false_positive text,
    severity_color text NOT NULL,
    dup_hash text,
    vuln_duplicate text,
    false_positive_hash text,
    vuln_status text,
    jira_ticket text,
    title text,
    severity text,
    description text,
    "references" text,
    "resourceName" text,
    "resourceId" text,
    "cloudType" text,
    "cloudAccountId" text,
    solution text NOT NULL,
    scanner text NOT NULL,
    note text,
    updated_time timestamp with time zone,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.cloudscansresultsdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: cloudscansresultsdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.cloudscansresultsdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.cloudscansresultsdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: cloudscansresultsdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.cloudscansresultsdb_id_seq OWNED BY public.cloudscansresultsdb.id;


--
-- Name: django_admin_log; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.django_admin_log (
    id integer NOT NULL,
    action_time timestamp with time zone NOT NULL,
    object_id text,
    object_repr character varying(200) NOT NULL,
    action_flag smallint NOT NULL,
    change_message text NOT NULL,
    content_type_id integer,
    user_id integer NOT NULL,
    CONSTRAINT django_admin_log_action_flag_check CHECK ((action_flag >= 0))
);


ALTER TABLE public.django_admin_log OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: django_admin_log_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.django_admin_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.django_admin_log_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: django_admin_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.django_admin_log_id_seq OWNED BY public.django_admin_log.id;


--
-- Name: django_content_type; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.django_content_type (
    id integer NOT NULL,
    app_label character varying(100) NOT NULL,
    model character varying(100) NOT NULL
);


ALTER TABLE public.django_content_type OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: django_content_type_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.django_content_type_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.django_content_type_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: django_content_type_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.django_content_type_id_seq OWNED BY public.django_content_type.id;


--
-- Name: django_migrations; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.django_migrations (
    id integer NOT NULL,
    app character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    applied timestamp with time zone NOT NULL
);


ALTER TABLE public.django_migrations OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: django_migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.django_migrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.django_migrations_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: django_migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.django_migrations_id_seq OWNED BY public.django_migrations.id;


--
-- Name: django_session; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.django_session (
    session_key character varying(40) NOT NULL,
    session_data text NOT NULL,
    expire_date timestamp with time zone NOT NULL
);


ALTER TABLE public.django_session OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: docklescandb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.docklescandb (
    id integer NOT NULL,
    scan_id uuid,
    rescan_id text,
    scan_date text,
    project_name text,
    total_vuln integer,
    scan_status integer,
    date_time timestamp with time zone,
    total_dup integer,
    dockle_fatal integer,
    dockle_warn integer,
    dockle_info integer,
    dockle_pass integer,
    username character varying(256),
    updated_time timestamp with time zone,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.docklescandb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: docklescandb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.docklescandb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.docklescandb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: docklescandb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.docklescandb_id_seq OWNED BY public.docklescandb.id;


--
-- Name: docklescanresultsdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.docklescanresultsdb (
    id integer NOT NULL,
    scan_id uuid NOT NULL,
    rescan_id text,
    scan_date text NOT NULL,
    date_time timestamp with time zone,
    vuln_id uuid NOT NULL,
    false_positive text,
    vul_col text NOT NULL,
    dup_hash text,
    vuln_duplicate text,
    false_positive_hash text,
    vuln_status text,
    scanner text NOT NULL,
    username character varying(256),
    code text,
    title text,
    level text,
    alerts text,
    updated_time timestamp with time zone,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.docklescanresultsdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: docklescanresultsdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.docklescanresultsdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.docklescanresultsdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: docklescanresultsdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.docklescanresultsdb_id_seq OWNED BY public.docklescanresultsdb.id;


--
-- Name: inspecscandb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.inspecscandb (
    id integer NOT NULL,
    scan_id uuid,
    rescan_id text,
    scan_date text,
    project_name text,
    total_vuln integer,
    scan_status integer,
    date_time timestamp with time zone,
    total_dup integer,
    inspec_failed integer,
    inspec_passed integer,
    inspec_skipped integer,
    updated_time timestamp with time zone,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.inspecscandb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: inspecscandb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.inspecscandb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.inspecscandb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: inspecscandb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.inspecscandb_id_seq OWNED BY public.inspecscandb.id;


--
-- Name: inspecscanresultdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.inspecscanresultdb (
    id integer NOT NULL,
    scan_id uuid NOT NULL,
    rescan_id text,
    scan_date text NOT NULL,
    vuln_id uuid NOT NULL,
    date_time timestamp with time zone,
    false_positive text,
    vul_col text NOT NULL,
    dup_hash text,
    vuln_duplicate text,
    false_positive_hash text,
    vuln_status text,
    "Name" text,
    platform_name text,
    platform_release text,
    profiles_name text,
    profiles_sha256 text,
    profiles_title text,
    profiles_supports text,
    attributes_name text,
    attributes_options_description text,
    attributes_options_default text,
    groups_id text,
    groups_controls text,
    controls_id text,
    controls_title text,
    controls_desc text,
    controls_descriptions text,
    controls_impact text,
    controls_refs text,
    controls_tags_severity text,
    controls_tags_cis_id text,
    controls_tags_cis_control text,
    controls_tags_cis_level text,
    controls_tags_audit text,
    controls_tags_fix text,
    controls_tags_defaultvalue text,
    controls_code text,
    controls_source_location text,
    controls_results_status text,
    controls_results_code_desc text,
    controls_results_run_time text,
    controls_results_start_time text,
    controls_results_message text,
    controls_results_backtrace text,
    controls_tags_audit_text text,
    scanner text NOT NULL,
    username character varying(256),
    updated_time timestamp with time zone,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.inspecscanresultdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: inspecscanresultdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.inspecscanresultdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.inspecscanresultdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: inspecscanresultdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.inspecscanresultdb_id_seq OWNED BY public.inspecscanresultdb.id;


--
-- Name: jiraticketing_jirasetting; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.jiraticketing_jirasetting (
    id integer NOT NULL,
    setting_id uuid,
    jira_server text,
    jira_username text,
    jira_password text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.jiraticketing_jirasetting OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: jiraticketing_jirasetting_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.jiraticketing_jirasetting_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.jiraticketing_jirasetting_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: jiraticketing_jirasetting_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.jiraticketing_jirasetting_id_seq OWNED BY public.jiraticketing_jirasetting.id;


--
-- Name: monthdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.monthdb (
    id integer NOT NULL,
    month text,
    high integer NOT NULL,
    medium integer NOT NULL,
    low integer NOT NULL,
    updated_time timestamp with time zone,
    project_id integer,
    critical integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.monthdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: monthdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.monthdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.monthdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: monthdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.monthdb_id_seq OWNED BY public.monthdb.id;


--
-- Name: networkscandb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.networkscandb (
    id integer NOT NULL,
    scan_id uuid NOT NULL,
    ip inet,
    rescan_id text,
    scan_date text NOT NULL,
    scan_status text NOT NULL,
    total_vul integer,
    critical_vul integer,
    high_vul integer,
    medium_vul integer,
    low_vul integer,
    info_vul integer,
    date_time timestamp with time zone,
    rescan text,
    total_dup text,
    scanner text,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer,
    failure_reason text,
    updated_time timestamp with time zone,
    scan_type text,
    runner_pid text
);


ALTER TABLE public.networkscandb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: networkscanners_networkscandb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.networkscanners_networkscandb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.networkscanners_networkscandb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: networkscanners_networkscandb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.networkscanners_networkscandb_id_seq OWNED BY public.networkscandb.id;


--
-- Name: networkscanresultsdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.networkscanresultsdb (
    id integer NOT NULL,
    scan_id uuid NOT NULL,
    vuln_id uuid NOT NULL,
    title text NOT NULL,
    date_time timestamp with time zone,
    severity_color character varying(256),
    severity character varying(256),
    description text,
    solution text,
    port text,
    ip inet,
    scanner text NOT NULL,
    jira_ticket text,
    dup_hash text,
    vuln_duplicate text,
    false_positive text,
    vuln_status text,
    false_positive_hash text,
    project_id integer,
    updated_time timestamp with time zone,
    note text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.networkscanresultsdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: networkscanners_networkscanresultsdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.networkscanners_networkscanresultsdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.networkscanners_networkscanresultsdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: networkscanners_networkscanresultsdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.networkscanners_networkscanresultsdb_id_seq OWNED BY public.networkscanresultsdb.id;


--
-- Name: notifications_notification; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.notifications_notification (
    id integer NOT NULL,
    level character varying(20) NOT NULL,
    unread boolean NOT NULL,
    actor_object_id character varying(255) NOT NULL,
    verb character varying(255) NOT NULL,
    description text,
    target_object_id character varying(255),
    action_object_object_id character varying(255),
    "timestamp" timestamp with time zone NOT NULL,
    public boolean NOT NULL,
    action_object_content_type_id integer,
    actor_content_type_id integer NOT NULL,
    recipient_id integer NOT NULL,
    target_content_type_id integer,
    deleted boolean NOT NULL,
    emailed boolean NOT NULL,
    data text
);


ALTER TABLE public.notifications_notification OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: notifications_notification_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.notifications_notification_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.notifications_notification_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: notifications_notification_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.notifications_notification_id_seq OWNED BY public.notifications_notification.id;


--
-- Name: nvd_cache; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.nvd_cache (
    cve_id character varying(20) NOT NULL,
    cvss_score double precision,
    cvss_severity character varying(20),
    cvss_vector text,
    description text,
    "references" jsonb,
    source character varying(20) NOT NULL,
    fetched_at timestamp with time zone NOT NULL
);


ALTER TABLE public.nvd_cache OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: org_apikey; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.org_apikey (
    id integer NOT NULL,
    uu_id uuid NOT NULL,
    api_key character varying(255) NOT NULL,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    created_by_id integer,
    name character varying(255),
    organization_id integer NOT NULL
);


ALTER TABLE public.org_apikey OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: org_apikey_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.org_apikey_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.org_apikey_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: org_apikey_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.org_apikey_id_seq OWNED BY public.org_apikey.id;


--
-- Name: organization; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.organization (
    id integer NOT NULL,
    uu_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255) NOT NULL,
    logo character varying(255) NOT NULL,
    contact character varying(255) NOT NULL,
    token_time timestamp with time zone,
    address character varying(255) NOT NULL
);


ALTER TABLE public.organization OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: organization_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.organization_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.organization_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: organization_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.organization_id_seq OWNED BY public.organization.id;


--
-- Name: pentest_pentestscandb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.pentest_pentestscandb (
    id integer NOT NULL,
    scan_url character varying(200) NOT NULL,
    scan_id text NOT NULL,
    total_vul integer,
    high_vul integer,
    medium_vul integer,
    low_vul integer,
    date_time timestamp with time zone,
    pentest_type text,
    project_id integer,
    critical_vul integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.pentest_pentestscandb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: pentest_pentestscandb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.pentest_pentestscandb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.pentest_pentestscandb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: pentest_pentestscandb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.pentest_pentestscandb_id_seq OWNED BY public.pentest_pentestscandb.id;


--
-- Name: pentest_pentestscanresultsdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.pentest_pentestscanresultsdb (
    id integer NOT NULL,
    vuln_id text NOT NULL,
    scan_id text NOT NULL,
    date_time timestamp with time zone,
    rescan_id text,
    vuln_name text,
    severity text,
    severity_color text,
    vuln_url text,
    scan_url text NOT NULL,
    description text,
    solution text,
    request_header text,
    response_header text,
    reference text,
    vuln_status text,
    "Poc_Img" character varying(100),
    poc_description text,
    pentest_type text,
    project_id integer,
    note text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.pentest_pentestscanresultsdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: pentest_pentestscanresultsdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.pentest_pentestscanresultsdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.pentest_pentestscanresultsdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: pentest_pentestscanresultsdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.pentest_pentestscanresultsdb_id_seq OWNED BY public.pentest_pentestscanresultsdb.id;


--
-- Name: pentest_vulnerabilitydata; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.pentest_vulnerabilitydata (
    id integer NOT NULL,
    vuln_data_id text NOT NULL,
    vuln_name text NOT NULL,
    vuln_description text NOT NULL,
    vuln_severity text NOT NULL,
    vuln_remediation text NOT NULL,
    vuln_references text NOT NULL,
    date_time timestamp with time zone,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.pentest_vulnerabilitydata OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: pentest_vulnerabilitydata_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.pentest_vulnerabilitydata_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.pentest_vulnerabilitydata_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: pentest_vulnerabilitydata_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.pentest_vulnerabilitydata_id_seq OWNED BY public.pentest_vulnerabilitydata.id;


--
-- Name: project; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.project (
    id integer NOT NULL,
    uu_id uuid NOT NULL,
    project_name character varying(255) NOT NULL,
    project_start text NOT NULL,
    project_end text NOT NULL,
    project_owner text NOT NULL,
    project_disc text NOT NULL,
    project_status text NOT NULL,
    date_time timestamp with time zone,
    total_vuln integer,
    total_high integer,
    total_medium integer,
    total_low integer,
    total_open integer,
    total_false integer,
    total_close integer,
    total_net integer,
    total_web integer,
    total_static integer,
    high_net integer,
    high_web integer,
    high_static integer,
    medium_net integer,
    medium_web integer,
    medium_static integer,
    low_net integer,
    low_web integer,
    low_static integer,
    created_time timestamp with time zone NOT NULL,
    updated_time timestamp with time zone,
    is_active boolean NOT NULL,
    created_by_id integer,
    updated_by_id integer,
    critical_net integer,
    critical_static integer,
    critical_web integer,
    total_critical integer,
    critical_cloud integer,
    high_cloud integer,
    low_cloud integer,
    medium_cloud integer,
    total_cloud integer,
    organization_id integer NOT NULL
);


ALTER TABLE public.project OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: project_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.project_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.project_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: project_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.project_id_seq OWNED BY public.project.id;


--
-- Name: projectscandb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.projectscandb (
    id integer NOT NULL,
    project_url text NOT NULL,
    project_ip text NOT NULL,
    scan_type text NOT NULL,
    date_time timestamp with time zone,
    updated_time timestamp with time zone,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.projectscandb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: projectscandb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.projectscandb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.projectscandb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: projectscandb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.projectscandb_id_seq OWNED BY public.projectscandb.id;


--
-- Name: sitetree_tree; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.sitetree_tree (
    id integer NOT NULL,
    title character varying(100) NOT NULL,
    alias character varying(80) NOT NULL
);


ALTER TABLE public.sitetree_tree OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: sitetree_tree_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.sitetree_tree_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.sitetree_tree_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: sitetree_tree_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.sitetree_tree_id_seq OWNED BY public.sitetree_tree.id;


--
-- Name: sitetree_treeitem; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.sitetree_treeitem (
    id integer NOT NULL,
    title character varying(100) NOT NULL,
    hint character varying(200) NOT NULL,
    url character varying(200) NOT NULL,
    urlaspattern boolean NOT NULL,
    hidden boolean NOT NULL,
    alias character varying(80),
    description text NOT NULL,
    inmenu boolean NOT NULL,
    inbreadcrumbs boolean NOT NULL,
    insitetree boolean NOT NULL,
    access_loggedin boolean NOT NULL,
    access_guest boolean NOT NULL,
    access_restricted boolean NOT NULL,
    access_perm_type integer NOT NULL,
    sort_order integer NOT NULL,
    parent_id integer,
    tree_id integer NOT NULL
);


ALTER TABLE public.sitetree_treeitem OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: sitetree_treeitem_access_permissions; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.sitetree_treeitem_access_permissions (
    id integer NOT NULL,
    treeitem_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.sitetree_treeitem_access_permissions OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: sitetree_treeitem_access_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.sitetree_treeitem_access_permissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.sitetree_treeitem_access_permissions_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: sitetree_treeitem_access_permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.sitetree_treeitem_access_permissions_id_seq OWNED BY public.sitetree_treeitem_access_permissions.id;


--
-- Name: sitetree_treeitem_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.sitetree_treeitem_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.sitetree_treeitem_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: sitetree_treeitem_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.sitetree_treeitem_id_seq OWNED BY public.sitetree_treeitem.id;


--
-- Name: staticscanresultsdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.staticscanresultsdb (
    id integer NOT NULL,
    scan_id uuid NOT NULL,
    rescan_id text,
    date_time timestamp with time zone,
    vuln_id uuid NOT NULL,
    false_positive text,
    severity_color text NOT NULL,
    dup_hash text,
    vuln_duplicate text,
    false_positive_hash text,
    vuln_status text,
    jira_ticket text,
    title text,
    severity text,
    description text,
    "references" text,
    "fileName" text,
    "filePath" text,
    solution text NOT NULL,
    scanner text NOT NULL,
    project_id integer,
    updated_time timestamp with time zone,
    note text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.staticscanresultsdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: staticscanners_staticscanresultsdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.staticscanners_staticscanresultsdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.staticscanners_staticscanresultsdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: staticscanners_staticscanresultsdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.staticscanners_staticscanresultsdb_id_seq OWNED BY public.staticscanresultsdb.id;


--
-- Name: staticscansdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.staticscansdb (
    id integer NOT NULL,
    project_name text,
    scan_id uuid NOT NULL,
    rescan_id text,
    scan_date text NOT NULL,
    scan_status text NOT NULL,
    total_vul integer,
    critical_vul integer,
    high_vul integer,
    medium_vul integer,
    low_vul integer,
    info_vul integer,
    date_time timestamp with time zone,
    rescan text,
    total_dup text,
    scanner character varying(256),
    project_id integer,
    updated_time timestamp with time zone,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.staticscansdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: staticscanners_staticscansdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.staticscanners_staticscansdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.staticscanners_staticscansdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: staticscanners_staticscansdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.staticscanners_staticscansdb_id_seq OWNED BY public.staticscansdb.id;


--
-- Name: taskscheduledb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.taskscheduledb (
    id integer NOT NULL,
    task_id text,
    target text,
    schedule_time text,
    project_id text,
    scanner text,
    periodic_task text,
    updated_time timestamp with time zone,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer,
    last_run_at timestamp with time zone,
    schedule_time_utc timestamp with time zone,
    scan_config jsonb,
    scan_type text
);


ALTER TABLE public.taskscheduledb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: taskscheduledb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.taskscheduledb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.taskscheduledb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: taskscheduledb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.taskscheduledb_id_seq OWNED BY public.taskscheduledb.id;


--
-- Name: token_blacklist_blacklistedtoken; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.token_blacklist_blacklistedtoken (
    id bigint NOT NULL,
    blacklisted_at timestamp with time zone NOT NULL,
    token_id bigint NOT NULL
);


ALTER TABLE public.token_blacklist_blacklistedtoken OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: token_blacklist_blacklistedtoken_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.token_blacklist_blacklistedtoken_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.token_blacklist_blacklistedtoken_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: token_blacklist_blacklistedtoken_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.token_blacklist_blacklistedtoken_id_seq OWNED BY public.token_blacklist_blacklistedtoken.id;


--
-- Name: token_blacklist_outstandingtoken; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.token_blacklist_outstandingtoken (
    id bigint NOT NULL,
    token text NOT NULL,
    created_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    user_id integer,
    jti character varying(255) NOT NULL
);


ALTER TABLE public.token_blacklist_outstandingtoken OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: token_blacklist_outstandingtoken_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.token_blacklist_outstandingtoken_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.token_blacklist_outstandingtoken_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: token_blacklist_outstandingtoken_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.token_blacklist_outstandingtoken_id_seq OWNED BY public.token_blacklist_outstandingtoken.id;


--
-- Name: tools_niktoresultdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.tools_niktoresultdb (
    id integer NOT NULL,
    scan_id text,
    scan_url text,
    nikto_scan_output text,
    date_time text,
    nikto_status text,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer,
    pid integer,
    pgid integer
);


ALTER TABLE public.tools_niktoresultdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_niktoresultdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.tools_niktoresultdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tools_niktoresultdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_niktoresultdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.tools_niktoresultdb_id_seq OWNED BY public.tools_niktoresultdb.id;


--
-- Name: tools_niktovulndb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.tools_niktovulndb (
    id integer NOT NULL,
    vuln_id uuid,
    scan_id uuid,
    scan_url text,
    discription text,
    targetip text,
    hostname text,
    port text,
    uri text,
    httpmethod text,
    testlinks text,
    osvdb text,
    false_positive text,
    jira_ticket text,
    vuln_status text,
    dup_hash text,
    vuln_duplicate text,
    false_positive_hash text,
    date_time text,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.tools_niktovulndb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_niktovulndb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.tools_niktovulndb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tools_niktovulndb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_niktovulndb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.tools_niktovulndb_id_seq OWNED BY public.tools_niktovulndb.id;


--
-- Name: tools_nmapresultdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.tools_nmapresultdb (
    id integer NOT NULL,
    scan_id text,
    ip_address text,
    protocol text,
    port text,
    state text,
    reason text,
    reason_ttl text,
    version text,
    extrainfo text,
    name text,
    conf text,
    method text,
    type_p text,
    osfamily text,
    vendor text,
    osgen text,
    accuracy text,
    cpe text,
    used_state text,
    used_portid text,
    used_proto text,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.tools_nmapresultdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_nmapresultdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.tools_nmapresultdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tools_nmapresultdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_nmapresultdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.tools_nmapresultdb_id_seq OWNED BY public.tools_nmapresultdb.id;


--
-- Name: tools_nmapscandb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.tools_nmapscandb (
    id integer NOT NULL,
    scan_id text,
    scan_ip text,
    total_ports text,
    total_open_ports text,
    total_close_ports text,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer,
    pid integer,
    pgid integer
);


ALTER TABLE public.tools_nmapscandb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_nmapscandb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.tools_nmapscandb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tools_nmapscandb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_nmapscandb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.tools_nmapscandb_id_seq OWNED BY public.tools_nmapscandb.id;


--
-- Name: tools_nmapvulnersportresultdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.tools_nmapvulnersportresultdb (
    nmapresultdb_ptr_id integer NOT NULL,
    vulners_extrainfo text
);


ALTER TABLE public.tools_nmapvulnersportresultdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_sslscanresultdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.tools_sslscanresultdb (
    id integer NOT NULL,
    scan_id text,
    scan_url text,
    sslscan_output text,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.tools_sslscanresultdb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_sslscanresultdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.tools_sslscanresultdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tools_sslscanresultdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: tools_sslscanresultdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.tools_sslscanresultdb_id_seq OWNED BY public.tools_sslscanresultdb.id;


--
-- Name: unified_scan_config; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.unified_scan_config (
    scan_id uuid NOT NULL,
    scan_type character varying(20) NOT NULL,
    scanner_name character varying(50) NOT NULL,
    target text NOT NULL,
    targets jsonb NOT NULL,
    profile character varying(50),
    options jsonb NOT NULL,
    timeout integer NOT NULL,
    schedule_config jsonb,
    schedule_type character varying(20),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    created_by_id integer,
    organization_id integer NOT NULL,
    project_id integer
);


ALTER TABLE public.unified_scan_config OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: unified_scan_result; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.unified_scan_result (
    scan_id uuid NOT NULL,
    result_id uuid NOT NULL,
    scan_type character varying(20) NOT NULL,
    scanner_name character varying(50) NOT NULL,
    target text NOT NULL,
    vulnerability jsonb NOT NULL,
    title character varying(500) NOT NULL,
    description text NOT NULL,
    solution text NOT NULL,
    severity character varying(20) NOT NULL,
    cvss_score numeric(4,1),
    cvss_vector character varying(100) NOT NULL,
    cwe_id character varying(20) NOT NULL,
    cve_id character varying(20) NOT NULL,
    url text NOT NULL,
    host character varying(255) NOT NULL,
    port character varying(10) NOT NULL,
    path character varying(500) NOT NULL,
    parameter character varying(255) NOT NULL,
    method character varying(10) NOT NULL,
    evidence text NOT NULL,
    request text NOT NULL,
    response text NOT NULL,
    payload text NOT NULL,
    dup_hash character varying(64) NOT NULL,
    false_positive boolean NOT NULL,
    duplicate boolean NOT NULL,
    vuln_status character varying(20) NOT NULL,
    "references" jsonb NOT NULL,
    tags jsonb NOT NULL,
    scan_status character varying(20) NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    failure_reason text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    created_by_id integer,
    organization_id integer NOT NULL,
    project_id integer
);


ALTER TABLE public.unified_scan_result OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: unified_scan_summary; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.unified_scan_summary (
    scan_id uuid NOT NULL,
    scan_type character varying(20) NOT NULL,
    scanner_name character varying(50) NOT NULL,
    target text NOT NULL,
    total_vulns integer NOT NULL,
    critical_count integer NOT NULL,
    high_count integer NOT NULL,
    medium_count integer NOT NULL,
    low_count integer NOT NULL,
    info_count integer NOT NULL,
    unknown_count integer NOT NULL,
    scan_status character varying(20) NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    failure_reason text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    created_by_id integer,
    organization_id integer NOT NULL,
    project_id integer
);


ALTER TABLE public.unified_scan_summary OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_login_history; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.user_login_history (
    id integer NOT NULL,
    logintime timestamp with time zone NOT NULL,
    logouttime timestamp with time zone,
    "IP" character varying(20) NOT NULL,
    user_id integer NOT NULL
);


ALTER TABLE public.user_login_history OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_login_history_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.user_login_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.user_login_history_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_login_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.user_login_history_id_seq OWNED BY public.user_login_history.id;


--
-- Name: user_profile; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.user_profile (
    id integer NOT NULL,
    password character varying(128) NOT NULL,
    last_login timestamp with time zone,
    is_superuser boolean NOT NULL,
    email character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    image character varying(100),
    is_active boolean NOT NULL,
    is_staff boolean NOT NULL,
    uu_id uuid NOT NULL,
    pass_token character varying(255),
    token_time timestamp with time zone,
    password_updt_time timestamp with time zone,
    organization_id integer NOT NULL,
    role_id integer,
    created_time timestamp with time zone,
    notify_critical_only boolean NOT NULL,
    notify_email boolean NOT NULL,
    notify_in_app boolean NOT NULL,
    notify_on_scan_complete boolean NOT NULL,
    notify_on_scan_fail boolean NOT NULL,
    notify_on_scan_start boolean NOT NULL
);


ALTER TABLE public.user_profile OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_profile_groups; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.user_profile_groups (
    id integer NOT NULL,
    userprofile_id integer NOT NULL,
    group_id integer NOT NULL
);


ALTER TABLE public.user_profile_groups OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_profile_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.user_profile_groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.user_profile_groups_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_profile_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.user_profile_groups_id_seq OWNED BY public.user_profile_groups.id;


--
-- Name: user_profile_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.user_profile_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.user_profile_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_profile_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.user_profile_id_seq OWNED BY public.user_profile.id;


--
-- Name: user_profile_user_permissions; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.user_profile_user_permissions (
    id integer NOT NULL,
    userprofile_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.user_profile_user_permissions OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_profile_user_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.user_profile_user_permissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.user_profile_user_permissions_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_profile_user_permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.user_profile_user_permissions_id_seq OWNED BY public.user_profile_user_permissions.id;


--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.user_roles (
    id integer NOT NULL,
    role character varying(255) NOT NULL,
    description character varying(255) NOT NULL,
    uu_id uuid NOT NULL
);


ALTER TABLE public.user_roles OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_roles_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.user_roles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.user_roles_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: user_roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.user_roles_id_seq OWNED BY public.user_roles.id;


--
-- Name: webscanResultsdb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public."webscanResultsdb" (
    id integer NOT NULL,
    vuln_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    rescan_id text,
    url text NOT NULL,
    title text NOT NULL,
    solution text NOT NULL,
    description text NOT NULL,
    severity_color text NOT NULL,
    severity text,
    date_time timestamp with time zone,
    false_positive text,
    jira_ticket text,
    vuln_status text,
    dup_hash text,
    vuln_duplicate text,
    false_positive_hash text,
    scanner text NOT NULL,
    instance text NOT NULL,
    reference text NOT NULL,
    project_id integer,
    updated_time timestamp with time zone,
    note text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer,
    scan_phase character varying(16),
    cvss_score double precision,
    mitre_techniques text,
    risk_score double precision
);


ALTER TABLE public."webscanResultsdb" OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscandb; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.webscandb (
    id integer NOT NULL,
    scan_url character varying(200) NOT NULL,
    scan_id uuid NOT NULL,
    rescan_id text,
    scan_date text NOT NULL,
    scan_status text NOT NULL,
    total_vul integer,
    critical_vul integer,
    high_vul integer,
    medium_vul integer,
    low_vul integer,
    info_vul integer,
    date_time timestamp with time zone,
    rescan text,
    total_dup text,
    scanner text,
    project_id integer,
    updated_time timestamp with time zone NOT NULL,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer,
    failure_reason text,
    zap_ascan_id text,
    scan_type text
);


ALTER TABLE public.webscandb OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_burp_issue_definitions; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.webscanners_burp_issue_definitions (
    id integer NOT NULL,
    remediation text,
    issue_type_id text,
    description text,
    reference text,
    vulnerability_classifications text,
    name text,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.webscanners_burp_issue_definitions OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_burp_issue_definitions_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.webscanners_burp_issue_definitions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webscanners_burp_issue_definitions_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_burp_issue_definitions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.webscanners_burp_issue_definitions_id_seq OWNED BY public.webscanners_burp_issue_definitions.id;


--
-- Name: webscanners_cookie_db; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.webscanners_cookie_db (
    id integer NOT NULL,
    url text NOT NULL,
    cookie text NOT NULL
);


ALTER TABLE public.webscanners_cookie_db OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_cookie_db_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.webscanners_cookie_db_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webscanners_cookie_db_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_cookie_db_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.webscanners_cookie_db_id_seq OWNED BY public.webscanners_cookie_db.id;


--
-- Name: webscanners_email_config_db; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.webscanners_email_config_db (
    id integer NOT NULL,
    email_id_from character varying(254) NOT NULL,
    email_subject text NOT NULL,
    email_message text NOT NULL,
    email_id_to character varying(254) NOT NULL,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.webscanners_email_config_db OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_email_config_db_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.webscanners_email_config_db_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webscanners_email_config_db_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_email_config_db_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.webscanners_email_config_db_id_seq OWNED BY public.webscanners_email_config_db.id;


--
-- Name: webscanners_excluded_db; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.webscanners_excluded_db (
    id integer NOT NULL,
    exclude_url text NOT NULL
);


ALTER TABLE public.webscanners_excluded_db OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_excluded_db_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.webscanners_excluded_db_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webscanners_excluded_db_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_excluded_db_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.webscanners_excluded_db_id_seq OWNED BY public.webscanners_excluded_db.id;


--
-- Name: webscanners_task_schedule_db; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.webscanners_task_schedule_db (
    id integer NOT NULL,
    task_id text,
    target text,
    schedule_time text,
    scanner text,
    periodic_task text,
    project_id integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer,
    last_run_at timestamp with time zone,
    schedule_time_utc timestamp with time zone,
    scan_config jsonb,
    scan_type text
);


ALTER TABLE public.webscanners_task_schedule_db OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_task_schedule_db_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.webscanners_task_schedule_db_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webscanners_task_schedule_db_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_task_schedule_db_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.webscanners_task_schedule_db_id_seq OWNED BY public.webscanners_task_schedule_db.id;


--
-- Name: webscanners_web_scan_db; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.webscanners_web_scan_db (
    id integer NOT NULL,
    scan_url character varying(200) NOT NULL,
    scan_id uuid NOT NULL,
    scan_date text NOT NULL,
    scan_status text NOT NULL,
    total_vul integer NOT NULL,
    high_vul integer NOT NULL,
    medium_vul integer NOT NULL,
    low_vul integer NOT NULL,
    info_vuln integer NOT NULL,
    scanner text NOT NULL,
    project_id integer,
    critical_vul integer,
    created_by_id integer,
    created_time timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    organization_id integer NOT NULL,
    updated_by_id integer
);


ALTER TABLE public.webscanners_web_scan_db OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_web_scan_db_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.webscanners_web_scan_db_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webscanners_web_scan_db_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_web_scan_db_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.webscanners_web_scan_db_id_seq OWNED BY public.webscanners_web_scan_db.id;


--
-- Name: webscanners_webscanresultsdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.webscanners_webscanresultsdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webscanners_webscanresultsdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_webscanresultsdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.webscanners_webscanresultsdb_id_seq OWNED BY public."webscanResultsdb".id;


--
-- Name: webscanners_webscansdb_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.webscanners_webscansdb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webscanners_webscansdb_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_webscansdb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.webscanners_webscansdb_id_seq OWNED BY public.webscandb.id;


--
-- Name: webscanners_zap_spider_db; Type: TABLE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE TABLE public.webscanners_zap_spider_db (
    id integer NOT NULL,
    spider_url text NOT NULL,
    spider_scanid text NOT NULL,
    urls_num text NOT NULL
);


ALTER TABLE public.webscanners_zap_spider_db OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_zap_spider_db_id_seq; Type: SEQUENCE; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE SEQUENCE public.webscanners_zap_spider_db_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webscanners_zap_spider_db_id_seq OWNER TO "131jCYxVFiKBJokuv2Kg4aWV9Ld";

--
-- Name: webscanners_zap_spider_db_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER SEQUENCE public.webscanners_zap_spider_db_id_seq OWNED BY public.webscanners_zap_spider_db.id;


--
-- Name: archerysettings_arachnisettingsdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_arachnisettingsdb ALTER COLUMN id SET DEFAULT nextval('public.archerysettings_arachnisettingsdb_id_seq'::regclass);


--
-- Name: archerysettings_burpsettingdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_burpsettingdb ALTER COLUMN id SET DEFAULT nextval('public.archerysettings_burpsettingdb_id_seq'::regclass);


--
-- Name: archerysettings_emaildb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_emaildb ALTER COLUMN id SET DEFAULT nextval('public.archerysettings_emaildb_id_seq'::regclass);


--
-- Name: archerysettings_niktosettingdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_niktosettingdb ALTER COLUMN id SET DEFAULT nextval('public.archerysettings_niktosettingdb_id_seq'::regclass);


--
-- Name: archerysettings_nmapsettingdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapsettingdb ALTER COLUMN id SET DEFAULT nextval('public.archerysettings_nmapsettingdb_id_seq'::regclass);


--
-- Name: archerysettings_nmapvulnerssettingdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapvulnerssettingdb ALTER COLUMN id SET DEFAULT nextval('public.archerysettings_nmapvulnerssettingdb_id_seq'::regclass);


--
-- Name: archerysettings_openvassettingdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_openvassettingdb ALTER COLUMN id SET DEFAULT nextval('public.archerysettings_openvassettingdb_id_seq'::regclass);


--
-- Name: archerysettings_settingsdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_settingsdb ALTER COLUMN id SET DEFAULT nextval('public.archerysettings_settingsdb_id_seq'::regclass);


--
-- Name: archerysettings_zapsettingsdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_zapsettingsdb ALTER COLUMN id SET DEFAULT nextval('public.archerysettings_zapsettingsdb_id_seq'::regclass);


--
-- Name: auth_group id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_group ALTER COLUMN id SET DEFAULT nextval('public.auth_group_id_seq'::regclass);


--
-- Name: auth_group_permissions id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_group_permissions ALTER COLUMN id SET DEFAULT nextval('public.auth_group_permissions_id_seq'::regclass);


--
-- Name: auth_permission id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_permission ALTER COLUMN id SET DEFAULT nextval('public.auth_permission_id_seq'::regclass);


--
-- Name: cicd_scannercommand id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicd_scannercommand ALTER COLUMN id SET DEFAULT nextval('public.cicd_scannercommand_id_seq'::regclass);


--
-- Name: cicddb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicddb ALTER COLUMN id SET DEFAULT nextval('public.cicddb_id_seq'::regclass);


--
-- Name: cloudscansdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansdb ALTER COLUMN id SET DEFAULT nextval('public.cloudscansdb_id_seq'::regclass);


--
-- Name: cloudscansresultsdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansresultsdb ALTER COLUMN id SET DEFAULT nextval('public.cloudscansresultsdb_id_seq'::regclass);


--
-- Name: django_admin_log id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_admin_log ALTER COLUMN id SET DEFAULT nextval('public.django_admin_log_id_seq'::regclass);


--
-- Name: django_content_type id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_content_type ALTER COLUMN id SET DEFAULT nextval('public.django_content_type_id_seq'::regclass);


--
-- Name: django_migrations id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_migrations ALTER COLUMN id SET DEFAULT nextval('public.django_migrations_id_seq'::regclass);


--
-- Name: docklescandb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescandb ALTER COLUMN id SET DEFAULT nextval('public.docklescandb_id_seq'::regclass);


--
-- Name: docklescanresultsdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescanresultsdb ALTER COLUMN id SET DEFAULT nextval('public.docklescanresultsdb_id_seq'::regclass);


--
-- Name: inspecscandb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscandb ALTER COLUMN id SET DEFAULT nextval('public.inspecscandb_id_seq'::regclass);


--
-- Name: inspecscanresultdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscanresultdb ALTER COLUMN id SET DEFAULT nextval('public.inspecscanresultdb_id_seq'::regclass);


--
-- Name: jiraticketing_jirasetting id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.jiraticketing_jirasetting ALTER COLUMN id SET DEFAULT nextval('public.jiraticketing_jirasetting_id_seq'::regclass);


--
-- Name: monthdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.monthdb ALTER COLUMN id SET DEFAULT nextval('public.monthdb_id_seq'::regclass);


--
-- Name: networkscandb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscandb ALTER COLUMN id SET DEFAULT nextval('public.networkscanners_networkscandb_id_seq'::regclass);


--
-- Name: networkscanresultsdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscanresultsdb ALTER COLUMN id SET DEFAULT nextval('public.networkscanners_networkscanresultsdb_id_seq'::regclass);


--
-- Name: notifications_notification id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.notifications_notification ALTER COLUMN id SET DEFAULT nextval('public.notifications_notification_id_seq'::regclass);


--
-- Name: org_apikey id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.org_apikey ALTER COLUMN id SET DEFAULT nextval('public.org_apikey_id_seq'::regclass);


--
-- Name: organization id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.organization ALTER COLUMN id SET DEFAULT nextval('public.organization_id_seq'::regclass);


--
-- Name: pentest_pentestscandb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscandb ALTER COLUMN id SET DEFAULT nextval('public.pentest_pentestscandb_id_seq'::regclass);


--
-- Name: pentest_pentestscanresultsdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscanresultsdb ALTER COLUMN id SET DEFAULT nextval('public.pentest_pentestscanresultsdb_id_seq'::regclass);


--
-- Name: pentest_vulnerabilitydata id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_vulnerabilitydata ALTER COLUMN id SET DEFAULT nextval('public.pentest_vulnerabilitydata_id_seq'::regclass);


--
-- Name: project id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.project ALTER COLUMN id SET DEFAULT nextval('public.project_id_seq'::regclass);


--
-- Name: projectscandb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.projectscandb ALTER COLUMN id SET DEFAULT nextval('public.projectscandb_id_seq'::regclass);


--
-- Name: sitetree_tree id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_tree ALTER COLUMN id SET DEFAULT nextval('public.sitetree_tree_id_seq'::regclass);


--
-- Name: sitetree_treeitem id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem ALTER COLUMN id SET DEFAULT nextval('public.sitetree_treeitem_id_seq'::regclass);


--
-- Name: sitetree_treeitem_access_permissions id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem_access_permissions ALTER COLUMN id SET DEFAULT nextval('public.sitetree_treeitem_access_permissions_id_seq'::regclass);


--
-- Name: staticscanresultsdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscanresultsdb ALTER COLUMN id SET DEFAULT nextval('public.staticscanners_staticscanresultsdb_id_seq'::regclass);


--
-- Name: staticscansdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscansdb ALTER COLUMN id SET DEFAULT nextval('public.staticscanners_staticscansdb_id_seq'::regclass);


--
-- Name: taskscheduledb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.taskscheduledb ALTER COLUMN id SET DEFAULT nextval('public.taskscheduledb_id_seq'::regclass);


--
-- Name: token_blacklist_blacklistedtoken id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.token_blacklist_blacklistedtoken ALTER COLUMN id SET DEFAULT nextval('public.token_blacklist_blacklistedtoken_id_seq'::regclass);


--
-- Name: token_blacklist_outstandingtoken id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.token_blacklist_outstandingtoken ALTER COLUMN id SET DEFAULT nextval('public.token_blacklist_outstandingtoken_id_seq'::regclass);


--
-- Name: tools_niktoresultdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktoresultdb ALTER COLUMN id SET DEFAULT nextval('public.tools_niktoresultdb_id_seq'::regclass);


--
-- Name: tools_niktovulndb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktovulndb ALTER COLUMN id SET DEFAULT nextval('public.tools_niktovulndb_id_seq'::regclass);


--
-- Name: tools_nmapresultdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapresultdb ALTER COLUMN id SET DEFAULT nextval('public.tools_nmapresultdb_id_seq'::regclass);


--
-- Name: tools_nmapscandb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapscandb ALTER COLUMN id SET DEFAULT nextval('public.tools_nmapscandb_id_seq'::regclass);


--
-- Name: tools_sslscanresultdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_sslscanresultdb ALTER COLUMN id SET DEFAULT nextval('public.tools_sslscanresultdb_id_seq'::regclass);


--
-- Name: user_login_history id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_login_history ALTER COLUMN id SET DEFAULT nextval('public.user_login_history_id_seq'::regclass);


--
-- Name: user_profile id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile ALTER COLUMN id SET DEFAULT nextval('public.user_profile_id_seq'::regclass);


--
-- Name: user_profile_groups id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_groups ALTER COLUMN id SET DEFAULT nextval('public.user_profile_groups_id_seq'::regclass);


--
-- Name: user_profile_user_permissions id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_user_permissions ALTER COLUMN id SET DEFAULT nextval('public.user_profile_user_permissions_id_seq'::regclass);


--
-- Name: user_roles id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_roles ALTER COLUMN id SET DEFAULT nextval('public.user_roles_id_seq'::regclass);


--
-- Name: webscanResultsdb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public."webscanResultsdb" ALTER COLUMN id SET DEFAULT nextval('public.webscanners_webscanresultsdb_id_seq'::regclass);


--
-- Name: webscandb id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscandb ALTER COLUMN id SET DEFAULT nextval('public.webscanners_webscansdb_id_seq'::regclass);


--
-- Name: webscanners_burp_issue_definitions id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_burp_issue_definitions ALTER COLUMN id SET DEFAULT nextval('public.webscanners_burp_issue_definitions_id_seq'::regclass);


--
-- Name: webscanners_cookie_db id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_cookie_db ALTER COLUMN id SET DEFAULT nextval('public.webscanners_cookie_db_id_seq'::regclass);


--
-- Name: webscanners_email_config_db id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_email_config_db ALTER COLUMN id SET DEFAULT nextval('public.webscanners_email_config_db_id_seq'::regclass);


--
-- Name: webscanners_excluded_db id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_excluded_db ALTER COLUMN id SET DEFAULT nextval('public.webscanners_excluded_db_id_seq'::regclass);


--
-- Name: webscanners_task_schedule_db id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_task_schedule_db ALTER COLUMN id SET DEFAULT nextval('public.webscanners_task_schedule_db_id_seq'::regclass);


--
-- Name: webscanners_web_scan_db id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_web_scan_db ALTER COLUMN id SET DEFAULT nextval('public.webscanners_web_scan_db_id_seq'::regclass);


--
-- Name: webscanners_zap_spider_db id; Type: DEFAULT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_zap_spider_db ALTER COLUMN id SET DEFAULT nextval('public.webscanners_zap_spider_db_id_seq'::regclass);


--
-- Data for Name: archerysettings_arachnisettingsdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.archerysettings_arachnisettingsdb (id, setting_id, arachni_url, arachni_port, arachni_user, arachni_pass, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: archerysettings_burpsettingdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.archerysettings_burpsettingdb (id, setting_id, burp_url, burp_port, burp_api_key, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: archerysettings_emaildb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.archerysettings_emaildb (id, setting_id, subject, message, recipient_list, created_by_id, created_time, is_active, organization_id, updated_by_id, smtp_host, smtp_port, smtp_use_tls, smtp_user, smtp_password, sender_email) FROM stdin;
1	244174ba-a2b3-4b5c-8454-c52ba7733ab6	ArcherySec Notification		immahkali939@gmail.com	\N	2026-09-12 12:16:31.305924+00	t	1	\N	smtp.gmail.com	587	t	immahkali939@gmail.com	ImN5Zmhkd3BvdWpncnR4ZWki:1x5Mel:ihpA5nF1WUhKi_se86I5aZc_M2W-whGTCXSVEv2kbv0	immahkali939@gmail.com
\.


--
-- Data for Name: archerysettings_niktosettingdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.archerysettings_niktosettingdb (id, setting_id, binary_path, enabled, created_time, is_active, organization_id, created_by_id, updated_by_id) FROM stdin;
1	3421b9b4-5f7b-406a-9a28-c16554a1e259		t	2026-09-12 12:16:31.322486+00	t	1	\N	\N
\.


--
-- Data for Name: archerysettings_nmapsettingdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.archerysettings_nmapsettingdb (id, setting_id, binary_path, enabled, created_time, is_active, organization_id, created_by_id, updated_by_id) FROM stdin;
1	ea186a94-938b-47ad-a0bf-43ed88103d08		t	2026-09-12 12:16:31.31436+00	t	1	\N	\N
\.


--
-- Data for Name: archerysettings_nmapvulnerssettingdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.archerysettings_nmapvulnerssettingdb (id, setting_id, enabled, version, online, timing, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: archerysettings_openvassettingdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.archerysettings_openvassettingdb (id, setting_id, host, port, enabled, "user", password, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
1	7ea4439b-1142-4e7e-8290-3a7550a04d4d	customarcherysecopenvas	9390	t	admin	admin	\N	2026-09-12 12:16:31.292768+00	t	1	\N
\.


--
-- Data for Name: archerysettings_settingsdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.archerysettings_settingsdb (id, setting_id, setting_name, setting_scanner, setting_status, created_time, created_by_id, is_active, organization_id, updated_by_id) FROM stdin;
1	c4bb60a3-b24d-4ed6-8526-22b215415ad6	\N	Jira	f	2026-09-12 12:16:31.287418+00	\N	t	1	\N
3	9870cf52-b0e6-413b-b50e-59682451d5f1	\N	Email	f	2026-09-12 12:16:31.308604+00	\N	t	1	\N
4	63442abc-aba8-4585-88c5-e4d05a4e794c	\N	Nmap	t	2026-09-12 12:17:02.921572+00	\N	t	1	\N
5	068429bb-1a26-4908-8bff-51eef1f5d4d7	\N	Nikto	t	2026-09-12 12:17:02.925586+00	\N	t	1	\N
6	69de3221-1d33-41fe-a618-c32f697aec68	Zap	Zap	t	2026-09-12 12:17:02.931622+00	1	t	1	\N
2	66e5a21f-fa82-428d-a1fc-31c87c0bd681	\N	Openvas	t	2026-09-12 12:17:02.936208+00	\N	t	1	\N
\.


--
-- Data for Name: archerysettings_zapsettingsdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.archerysettings_zapsettingsdb (id, setting_id, zap_url, zap_api, zap_port, enabled, created_by_id, created_time, is_active, organization_id, updated_by_id, auth_method, logged_in_regex, login_url, password_field, password_value, username_field, username_value) FROM stdin;
1	\N	zapscanner	none	8090	t	1	2026-09-12 12:08:18.843989+00	t	1	1	none			password		username	
\.


--
-- Data for Name: audit_log; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.audit_log (id, action, resource_type, resource_id, details, ip_address, user_agent, created_at, user_id) FROM stdin;
514a98f4-64ce-4177-8fcc-7f0f7bdf75ea	login	user	immah@gmail.com	{}	172.18.0.1	curl/8.21.0	2026-09-12 12:09:09.071235+00	1
86ce6fc4-5c06-4ca8-8aa2-2c6ec592ec43	login	user	immah@gmail.com	{}	172.18.0.1	curl/8.21.0	2026-09-12 12:16:31.156872+00	1
\.


--
-- Data for Name: auth_group; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.auth_group (id, name) FROM stdin;
\.


--
-- Data for Name: auth_group_permissions; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.auth_group_permissions (id, group_id, permission_id) FROM stdin;
\.


--
-- Data for Name: auth_permission; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.auth_permission (id, name, content_type_id, codename) FROM stdin;
1	Can add zap_spider_db	1	add_zap_spider_db
2	Can change zap_spider_db	1	change_zap_spider_db
3	Can delete zap_spider_db	1	delete_zap_spider_db
4	Can view zap_spider_db	1	view_zap_spider_db
5	Can add cookie_db	2	add_cookie_db
6	Can change cookie_db	2	change_cookie_db
7	Can delete cookie_db	2	delete_cookie_db
8	Can view cookie_db	2	view_cookie_db
9	Can add email_config_db	3	add_email_config_db
10	Can change email_config_db	3	change_email_config_db
11	Can delete email_config_db	3	delete_email_config_db
12	Can view email_config_db	3	view_email_config_db
13	Can add excluded_db	4	add_excluded_db
14	Can change excluded_db	4	change_excluded_db
15	Can delete excluded_db	4	delete_excluded_db
16	Can view excluded_db	4	view_excluded_db
17	Can add task_schedule_db	5	add_task_schedule_db
18	Can change task_schedule_db	5	change_task_schedule_db
19	Can delete task_schedule_db	5	delete_task_schedule_db
20	Can view task_schedule_db	5	view_task_schedule_db
21	Can add web_scan_db	6	add_web_scan_db
22	Can change web_scan_db	6	change_web_scan_db
23	Can delete web_scan_db	6	delete_web_scan_db
24	Can view web_scan_db	6	view_web_scan_db
25	Can add web scan results db	7	add_webscanresultsdb
26	Can change web scan results db	7	change_webscanresultsdb
27	Can delete web scan results db	7	delete_webscanresultsdb
28	Can view web scan results db	7	view_webscanresultsdb
29	Can add web scans db	8	add_webscansdb
30	Can change web scans db	8	change_webscansdb
31	Can delete web scans db	8	delete_webscansdb
32	Can view web scans db	8	view_webscansdb
33	Can add burp_issue_definitions	9	add_burp_issue_definitions
34	Can change burp_issue_definitions	9	change_burp_issue_definitions
35	Can delete burp_issue_definitions	9	delete_burp_issue_definitions
36	Can view burp_issue_definitions	9	view_burp_issue_definitions
37	Can add month db	10	add_monthdb
38	Can change month db	10	change_monthdb
39	Can delete month db	10	delete_monthdb
40	Can view month db	10	view_monthdb
41	Can add project db	11	add_projectdb
42	Can change project db	11	change_projectdb
43	Can delete project db	11	delete_projectdb
44	Can view project db	11	view_projectdb
45	Can add project scan db	12	add_projectscandb
46	Can change project scan db	12	change_projectscandb
47	Can delete project scan db	12	delete_projectscandb
48	Can view project scan db	12	view_projectscandb
49	Can add arachni settings db	13	add_arachnisettingsdb
50	Can change arachni settings db	13	change_arachnisettingsdb
51	Can delete arachni settings db	13	delete_arachnisettingsdb
52	Can view arachni settings db	13	view_arachnisettingsdb
53	Can add burp setting db	14	add_burpsettingdb
54	Can change burp setting db	14	change_burpsettingdb
55	Can delete burp setting db	14	delete_burpsettingdb
56	Can view burp setting db	14	view_burpsettingdb
57	Can add Email Setting	15	add_emaildb
58	Can change Email Setting	15	change_emaildb
59	Can delete Email Setting	15	delete_emaildb
60	Can view Email Setting	15	view_emaildb
61	Can add nmap vulners setting db	16	add_nmapvulnerssettingdb
62	Can change nmap vulners setting db	16	change_nmapvulnerssettingdb
63	Can delete nmap vulners setting db	16	delete_nmapvulnerssettingdb
64	Can view nmap vulners setting db	16	view_nmapvulnerssettingdb
65	Can add openvas setting db	17	add_openvassettingdb
66	Can change openvas setting db	17	change_openvassettingdb
67	Can delete openvas setting db	17	delete_openvassettingdb
68	Can view openvas setting db	17	view_openvassettingdb
69	Can add settings db	18	add_settingsdb
70	Can change settings db	18	change_settingsdb
71	Can delete settings db	18	delete_settingsdb
72	Can view settings db	18	view_settingsdb
73	Can add zap settings db	19	add_zapsettingsdb
74	Can change zap settings db	19	change_zapsettingsdb
75	Can delete zap settings db	19	delete_zapsettingsdb
76	Can view zap settings db	19	view_zapsettingsdb
77	Can add nmap setting db	20	add_nmapsettingdb
78	Can change nmap setting db	20	change_nmapsettingdb
79	Can delete nmap setting db	20	delete_nmapsettingdb
80	Can view nmap setting db	20	view_nmapsettingdb
81	Can add nikto setting db	21	add_niktosettingdb
82	Can change nikto setting db	21	change_niktosettingdb
83	Can delete nikto setting db	21	delete_niktosettingdb
84	Can view nikto setting db	21	view_niktosettingdb
85	Can add org api key	22	add_orgapikey
86	Can change org api key	22	change_orgapikey
87	Can delete org api key	22	delete_orgapikey
88	Can view org api key	22	view_orgapikey
89	Can add network scan db	23	add_networkscandb
90	Can change network scan db	23	change_networkscandb
91	Can delete network scan db	23	delete_networkscandb
92	Can view network scan db	23	view_networkscandb
93	Can add network scan results db	24	add_networkscanresultsdb
188	Can view Token	47	view_token
94	Can change network scan results db	24	change_networkscanresultsdb
95	Can delete network scan results db	24	delete_networkscanresultsdb
96	Can view network scan results db	24	view_networkscanresultsdb
97	Can add task schedule db	25	add_taskscheduledb
98	Can change task schedule db	25	change_taskscheduledb
99	Can delete task schedule db	25	delete_taskscheduledb
100	Can view task schedule db	25	view_taskscheduledb
101	Can add static scan results db	26	add_staticscanresultsdb
102	Can change static scan results db	26	change_staticscanresultsdb
103	Can delete static scan results db	26	delete_staticscanresultsdb
104	Can view static scan results db	26	view_staticscanresultsdb
105	Can add static scans db	27	add_staticscansdb
106	Can change static scans db	27	change_staticscansdb
107	Can delete static scans db	27	delete_staticscansdb
108	Can view static scans db	27	view_staticscansdb
109	Can add cloud scans results db	28	add_cloudscansresultsdb
110	Can change cloud scans results db	28	change_cloudscansresultsdb
111	Can delete cloud scans results db	28	delete_cloudscansresultsdb
112	Can view cloud scans results db	28	view_cloudscansresultsdb
113	Can add cloud scans db	29	add_cloudscansdb
114	Can change cloud scans db	29	change_cloudscansdb
115	Can delete cloud scans db	29	delete_cloudscansdb
116	Can view cloud scans db	29	view_cloudscansdb
117	Can add jirasetting	30	add_jirasetting
118	Can change jirasetting	30	change_jirasetting
119	Can delete jirasetting	30	delete_jirasetting
120	Can view jirasetting	30	view_jirasetting
121	Can add cicd db	31	add_cicddb
122	Can change cicd db	31	change_cicddb
123	Can delete cicd db	31	delete_cicddb
124	Can view cicd db	31	view_cicddb
125	Can add scanner command	32	add_scannercommand
126	Can change scanner command	32	change_scannercommand
127	Can delete scanner command	32	delete_scannercommand
128	Can view scanner command	32	view_scannercommand
129	Can add nmap result db	33	add_nmapresultdb
130	Can change nmap result db	33	change_nmapresultdb
131	Can delete nmap result db	33	delete_nmapresultdb
132	Can view nmap result db	33	view_nmapresultdb
133	Can add nmap vulners port result db	34	add_nmapvulnersportresultdb
134	Can change nmap vulners port result db	34	change_nmapvulnersportresultdb
135	Can delete nmap vulners port result db	34	delete_nmapvulnersportresultdb
136	Can view nmap vulners port result db	34	view_nmapvulnersportresultdb
137	Can add sslscan result db	35	add_sslscanresultdb
138	Can change sslscan result db	35	change_sslscanresultdb
139	Can delete sslscan result db	35	delete_sslscanresultdb
140	Can view sslscan result db	35	view_sslscanresultdb
141	Can add nmap scan db	36	add_nmapscandb
142	Can change nmap scan db	36	change_nmapscandb
143	Can delete nmap scan db	36	delete_nmapscandb
144	Can view nmap scan db	36	view_nmapscandb
145	Can add nikto vuln db	37	add_niktovulndb
146	Can change nikto vuln db	37	change_niktovulndb
147	Can delete nikto vuln db	37	delete_niktovulndb
148	Can view nikto vuln db	37	view_niktovulndb
149	Can add nikto result db	38	add_niktoresultdb
150	Can change nikto result db	38	change_niktoresultdb
151	Can delete nikto result db	38	delete_niktoresultdb
152	Can view nikto result db	38	view_niktoresultdb
153	Can add vulnerability data	39	add_vulnerabilitydata
154	Can change vulnerability data	39	change_vulnerabilitydata
155	Can delete vulnerability data	39	delete_vulnerabilitydata
156	Can view vulnerability data	39	view_vulnerabilitydata
157	Can add pentest scan results db	40	add_pentestscanresultsdb
158	Can change pentest scan results db	40	change_pentestscanresultsdb
159	Can delete pentest scan results db	40	delete_pentestscanresultsdb
160	Can view pentest scan results db	40	view_pentestscanresultsdb
161	Can add pentest scan db	41	add_pentestscandb
162	Can change pentest scan db	41	change_pentestscandb
163	Can delete pentest scan db	41	delete_pentestscandb
164	Can view pentest scan db	41	view_pentestscandb
165	Can add log entry	42	add_logentry
166	Can change log entry	42	change_logentry
167	Can delete log entry	42	delete_logentry
168	Can view log entry	42	view_logentry
169	Can add permission	43	add_permission
170	Can change permission	43	change_permission
171	Can delete permission	43	delete_permission
172	Can view permission	43	view_permission
173	Can add group	44	add_group
174	Can change group	44	change_group
175	Can delete group	44	delete_group
176	Can view group	44	view_group
177	Can add content type	45	add_contenttype
178	Can change content type	45	change_contenttype
179	Can delete content type	45	delete_contenttype
180	Can view content type	45	view_contenttype
181	Can add session	46	add_session
182	Can change session	46	change_session
183	Can delete session	46	delete_session
184	Can view session	46	view_session
185	Can add Token	47	add_token
186	Can change Token	47	change_token
187	Can delete Token	47	delete_token
189	Can add token	48	add_tokenproxy
190	Can change token	48	change_tokenproxy
191	Can delete token	48	delete_tokenproxy
192	Can view token	48	view_tokenproxy
193	Can add Site Tree	49	add_tree
194	Can change Site Tree	49	change_tree
195	Can delete Site Tree	49	delete_tree
196	Can view Site Tree	49	view_tree
197	Can add Site Tree Item	50	add_treeitem
198	Can change Site Tree Item	50	change_treeitem
199	Can delete Site Tree Item	50	delete_treeitem
200	Can view Site Tree Item	50	view_treeitem
201	Can add inspec scan results db	51	add_inspecscanresultsdb
202	Can change inspec scan results db	51	change_inspecscanresultsdb
203	Can delete inspec scan results db	51	delete_inspecscanresultsdb
204	Can view inspec scan results db	51	view_inspecscanresultsdb
205	Can add inspec scan db	52	add_inspecscandb
206	Can change inspec scan db	52	change_inspecscandb
207	Can delete inspec scan db	52	delete_inspecscandb
208	Can view inspec scan db	52	view_inspecscandb
209	Can add dockle scan results db	53	add_docklescanresultsdb
210	Can change dockle scan results db	53	change_docklescanresultsdb
211	Can delete dockle scan results db	53	delete_docklescanresultsdb
212	Can view dockle scan results db	53	view_docklescanresultsdb
213	Can add dockle scan db	54	add_docklescandb
214	Can change dockle scan db	54	change_docklescandb
215	Can delete dockle scan db	54	delete_docklescandb
216	Can view dockle scan db	54	view_docklescandb
217	Can add Notification	55	add_notification
218	Can change Notification	55	change_notification
219	Can delete Notification	55	delete_notification
220	Can view Notification	55	view_notification
221	Can add organization	56	add_organization
222	Can change organization	56	change_organization
223	Can delete organization	56	delete_organization
224	Can view organization	56	view_organization
225	Can add user roles	57	add_userroles
226	Can change user roles	57	change_userroles
227	Can delete user roles	57	delete_userroles
228	Can view user roles	57	view_userroles
229	Can add user profile	58	add_userprofile
230	Can change user profile	58	change_userprofile
231	Can delete user profile	58	delete_userprofile
232	Can view user profile	58	view_userprofile
233	Can add user login history	59	add_userloginhistory
234	Can change user login history	59	change_userloginhistory
235	Can delete user login history	59	delete_userloginhistory
236	Can view user login history	59	view_userloginhistory
237	Can add blacklisted token	60	add_blacklistedtoken
238	Can change blacklisted token	60	change_blacklistedtoken
239	Can delete blacklisted token	60	delete_blacklistedtoken
240	Can view blacklisted token	60	view_blacklistedtoken
241	Can add outstanding token	61	add_outstandingtoken
242	Can change outstanding token	61	change_outstandingtoken
243	Can delete outstanding token	61	delete_outstandingtoken
244	Can view outstanding token	61	view_outstandingtoken
245	Can add unified scan summary	62	add_unifiedscansummary
246	Can change unified scan summary	62	change_unifiedscansummary
247	Can delete unified scan summary	62	delete_unifiedscansummary
248	Can view unified scan summary	62	view_unifiedscansummary
249	Can add unified scan result	63	add_unifiedscanresult
250	Can change unified scan result	63	change_unifiedscanresult
251	Can delete unified scan result	63	delete_unifiedscanresult
252	Can view unified scan result	63	view_unifiedscanresult
253	Can add unified scan config	64	add_unifiedscanconfig
254	Can change unified scan config	64	change_unifiedscanconfig
255	Can delete unified scan config	64	delete_unifiedscanconfig
256	Can view unified scan config	64	view_unifiedscanconfig
257	Can add NVD Cache Entry	65	add_nvdcache
258	Can change NVD Cache Entry	65	change_nvdcache
259	Can delete NVD Cache Entry	65	delete_nvdcache
260	Can view NVD Cache Entry	65	view_nvdcache
261	Can add Audit Log Entry	66	add_auditlog
262	Can change Audit Log Entry	66	change_auditlog
263	Can delete Audit Log Entry	66	delete_auditlog
264	Can view Audit Log Entry	66	view_auditlog
\.


--
-- Data for Name: authtoken_token; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.authtoken_token (key, created, user_id) FROM stdin;
\.


--
-- Data for Name: cicd_scannercommand; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.cicd_scannercommand (id, scanner, command, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: cicddb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.cicddb (id, cicd_id, name, description, threshold, date_time, threshold_count, build_id, commit_hash, branch_tag, repo, scm_server, build_server, total_vul, critical_vul, high_vul, medium_vul, low_vul, info_vul, project_id, command, scanner, target, target_name, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: cloudscansdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.cloudscansdb (id, "cloudAccountId", scan_id, rescan_id, scan_date, scan_status, total_vul, critical_vul, high_vul, medium_vul, low_vul, info_vul, date_time, rescan, total_dup, scanner, updated_time, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: cloudscansresultsdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.cloudscansresultsdb (id, scan_id, rescan_id, date_time, vuln_id, false_positive, severity_color, dup_hash, vuln_duplicate, false_positive_hash, vuln_status, jira_ticket, title, severity, description, "references", "resourceName", "resourceId", "cloudType", "cloudAccountId", solution, scanner, note, updated_time, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: django_admin_log; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.django_admin_log (id, action_time, object_id, object_repr, action_flag, change_message, content_type_id, user_id) FROM stdin;
\.


--
-- Data for Name: django_content_type; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.django_content_type (id, app_label, model) FROM stdin;
1	webscanners	zap_spider_db
2	webscanners	cookie_db
3	webscanners	email_config_db
4	webscanners	excluded_db
5	webscanners	task_schedule_db
6	webscanners	web_scan_db
7	webscanners	webscanresultsdb
8	webscanners	webscansdb
9	webscanners	burp_issue_definitions
10	projects	monthdb
11	projects	projectdb
12	projects	projectscandb
13	archerysettings	arachnisettingsdb
14	archerysettings	burpsettingdb
15	archerysettings	emaildb
16	archerysettings	nmapvulnerssettingdb
17	archerysettings	openvassettingdb
18	archerysettings	settingsdb
19	archerysettings	zapsettingsdb
20	archerysettings	nmapsettingdb
21	archerysettings	niktosettingdb
22	archeryapi	orgapikey
23	networkscanners	networkscandb
24	networkscanners	networkscanresultsdb
25	networkscanners	taskscheduledb
26	staticscanners	staticscanresultsdb
27	staticscanners	staticscansdb
28	cloudscanners	cloudscansresultsdb
29	cloudscanners	cloudscansdb
30	jiraticketing	jirasetting
31	cicd	cicddb
32	cicd	scannercommand
33	tools	nmapresultdb
34	tools	nmapvulnersportresultdb
35	tools	sslscanresultdb
36	tools	nmapscandb
37	tools	niktovulndb
38	tools	niktoresultdb
39	pentest	vulnerabilitydata
40	pentest	pentestscanresultsdb
41	pentest	pentestscandb
42	admin	logentry
43	auth	permission
44	auth	group
45	contenttypes	contenttype
46	sessions	session
47	authtoken	token
48	authtoken	tokenproxy
49	sitetree	tree
50	sitetree	treeitem
51	compliance	inspecscanresultsdb
52	compliance	inspecscandb
53	compliance	docklescanresultsdb
54	compliance	docklescandb
55	notifications	notification
56	user_management	organization
57	user_management	userroles
58	user_management	userprofile
59	authentication	userloginhistory
60	token_blacklist	blacklistedtoken
61	token_blacklist	outstandingtoken
62	scanners	unifiedscansummary
63	scanners	unifiedscanresult
64	scanners	unifiedscanconfig
65	scanners	nvdcache
66	scanners	auditlog
\.


--
-- Data for Name: django_migrations; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.django_migrations (id, app, name, applied) FROM stdin;
1	contenttypes	0001_initial	2026-09-12 12:06:20.096176+00
2	contenttypes	0002_remove_content_type_name	2026-09-12 12:06:20.170314+00
3	auth	0001_initial	2026-09-12 12:06:20.325105+00
4	auth	0002_alter_permission_name_max_length	2026-09-12 12:06:20.361503+00
5	auth	0003_alter_user_email_max_length	2026-09-12 12:06:20.390233+00
6	auth	0004_alter_user_username_opts	2026-09-12 12:06:20.418261+00
7	auth	0005_alter_user_last_login_null	2026-09-12 12:06:20.472794+00
8	auth	0006_require_contenttypes_0002	2026-09-12 12:06:20.502848+00
9	auth	0007_alter_validators_add_error_messages	2026-09-12 12:06:20.545595+00
10	auth	0008_alter_user_username_max_length	2026-09-12 12:06:20.663711+00
11	auth	0009_alter_user_last_name_max_length	2026-09-12 12:06:20.723434+00
12	auth	0010_alter_group_name_max_length	2026-09-12 12:06:20.761118+00
13	auth	0011_update_proxy_permissions	2026-09-12 12:06:20.821842+00
14	auth	0012_alter_user_first_name_max_length	2026-09-12 12:06:20.846919+00
15	user_management	0001_initial	2026-09-12 12:06:21.101818+00
16	admin	0001_initial	2026-09-12 12:06:21.176518+00
17	admin	0002_logentry_remove_auto_add	2026-09-12 12:06:21.25058+00
18	admin	0003_logentry_add_action_flag_choices	2026-09-12 12:06:21.325239+00
19	archeryapi	0001_initial	2026-09-12 12:06:21.435152+00
20	archeryapi	0002_orgapikey_name	2026-09-12 12:06:21.503824+00
21	archeryapi	0003_orgapikey_organization	2026-09-12 12:06:21.577561+00
22	archerysettings	0001_initial	2026-09-12 12:06:21.729+00
23	archerysettings	0002_auto_20230506_1302	2026-09-12 12:06:25.177782+00
24	archerysettings	0003_add_email_smtp_fields	2026-09-12 12:06:25.717669+00
25	archerysettings	0004_alter_emaildb_options	2026-09-12 12:06:25.819353+00
26	archerysettings	0005_nmap_nikto_connector_settings	2026-09-12 12:06:26.213377+00
27	archerysettings	0006_auto_20260831_1804	2026-09-12 12:06:27.329813+00
28	authentication	0001_initial	2026-09-12 12:06:27.941349+00
29	authtoken	0001_initial	2026-09-12 12:06:28.101431+00
30	authtoken	0002_auto_20160226_1747	2026-09-12 12:06:28.784058+00
31	authtoken	0003_tokenproxy	2026-09-12 12:06:28.817613+00
32	projects	0001_initial	2026-09-12 12:06:28.871623+00
33	projects	0002_project_db_username	2026-09-12 12:06:28.886778+00
34	projects	0003_auto_20201006_0027	2026-09-12 12:06:28.91884+00
35	projects	0004_project_db_total_medium	2026-09-12 12:06:28.937558+00
36	projects	0005_auto_20201007_1012	2026-09-12 12:06:29.009073+00
37	projects	0006_auto_20201008_0136	2026-09-12 12:06:29.112697+00
38	projects	0007_project_db_total_false	2026-09-12 12:06:29.136343+00
39	projects	0008_month_db	2026-09-12 12:06:29.16205+00
40	projects	0009_month_db_username	2026-09-12 12:06:29.172207+00
41	projects	0010_month_db_project_id	2026-09-12 12:06:29.188116+00
42	projects	0011_auto_20200609_0735	2026-09-12 12:06:29.246604+00
43	projects	0012_auto_20201010_1912	2026-09-12 12:06:29.6991+00
44	projects	0013_auto_20201010_1955	2026-09-12 12:06:29.775978+00
45	projects	0014_auto_20210719_1431	2026-09-12 12:06:29.903132+00
46	projects	0015_auto_20210719_1431	2026-09-12 12:06:30.24505+00
47	cicd	0001_initial	2026-09-12 12:06:30.347663+00
48	cicd	0002_auto_20210903_0408	2026-09-12 12:06:30.485405+00
49	cicd	0003_auto_20230506_1302	2026-09-12 12:06:32.044529+00
50	projects	0016_auto_20220824_0432	2026-09-12 12:06:32.581578+00
51	projects	0017_alter_monthdb_critical	2026-09-12 12:06:32.645325+00
52	cloudscanners	0001_initial	2026-09-12 12:06:32.978499+00
53	cloudscanners	0002_rename_project_name_cloudscansdb_cloudaccountid	2026-09-12 12:06:33.030798+00
54	cloudscanners	0003_auto_20230506_1302	2026-09-12 12:06:34.787821+00
55	compliance	0001_initial	2026-09-12 12:06:35.530739+00
56	compliance	0002_auto_20230506_1302	2026-09-12 12:06:39.213315+00
57	jiraticketing	0001_initial	2026-09-12 12:06:39.249854+00
58	jiraticketing	0002_auto_20230506_1302	2026-09-12 12:06:39.811068+00
59	networkscanners	0001_initial	2026-09-12 12:06:39.853797+00
60	networkscanners	0002_auto_20181031_0022	2026-09-12 12:06:40.285825+00
61	networkscanners	0003_auto_20181101_1604	2026-09-12 12:06:40.51374+00
62	networkscanners	0004_auto_20190207_0342	2026-09-12 12:06:40.59347+00
63	networkscanners	0005_nessus_scan_db_info_total	2026-09-12 12:06:40.626898+00
64	networkscanners	0006_scan_save_db_log_total	2026-09-12 12:06:40.63979+00
65	networkscanners	0007_nessus_report_db_severity_color	2026-09-12 12:06:40.656615+00
66	networkscanners	0008_auto_20200503_1201	2026-09-12 12:06:40.721801+00
67	networkscanners	0009_auto_20201002_1757	2026-09-12 12:06:40.811769+00
68	networkscanners	0010_auto_20201002_1836	2026-09-12 12:06:41.149868+00
69	networkscanners	0011_auto_20201002_1855	2026-09-12 12:06:41.169244+00
70	networkscanners	0012_auto_20201002_1950	2026-09-12 12:06:41.299943+00
71	networkscanners	0013_nessus_targets_db	2026-09-12 12:06:41.31903+00
72	networkscanners	0014_auto_20201004_1522	2026-09-12 12:06:41.347384+00
73	networkscanners	0015_auto_20201006_1429	2026-09-12 12:06:41.50952+00
74	networkscanners	0016_auto_20201006_1434	2026-09-12 12:06:41.526305+00
75	networkscanners	0017_auto_20201006_1440	2026-09-12 12:06:41.543001+00
76	networkscanners	0018_networkscandb_networkscanresultsdb	2026-09-12 12:06:41.578774+00
77	networkscanners	0019_auto_20210531_2000	2026-09-12 12:06:41.631366+00
78	networkscanners	0020_networkscanresultsdb_false_positive_hash	2026-09-12 12:06:41.656928+00
79	networkscanners	0021_auto_20210531_2022	2026-09-12 12:06:41.723629+00
80	networkscanners	0022_auto_20210705_1243	2026-09-12 12:06:41.756418+00
81	networkscanners	0023_auto_20210719_1431	2026-09-12 12:06:41.834297+00
82	networkscanners	0024_auto_20210719_1431	2026-09-12 12:06:42.334898+00
83	networkscanners	0025_networkscanresultsdb_note	2026-09-12 12:06:42.392795+00
84	networkscanners	0026_auto_20230506_1302	2026-09-12 12:06:45.006963+00
85	networkscanners	0027_networkscandb_failure_updated	2026-09-12 12:06:45.855556+00
86	networkscanners	0028_networkscandb_scan_type	2026-09-12 12:06:46.002966+00
87	networkscanners	0029_networkscandb_runner_pid	2026-09-12 12:06:46.16464+00
88	networkscanners	0030_task_schedule_fields	2026-09-12 12:06:46.467368+00
89	networkscanners	0031_task_schedule_scan_config	2026-09-12 12:06:46.740234+00
90	notifications	0001_initial	2026-09-12 12:06:46.951702+00
91	notifications	0002_auto_20150224_1134	2026-09-12 12:06:47.275386+00
92	notifications	0003_notification_data	2026-09-12 12:06:47.391193+00
93	notifications	0004_auto_20150826_1508	2026-09-12 12:06:47.835771+00
94	notifications	0005_auto_20160504_1520	2026-09-12 12:06:48.144311+00
95	notifications	0006_indexes	2026-09-12 12:06:48.770927+00
96	notifications	0007_add_timestamp_index	2026-09-12 12:06:48.888311+00
97	notifications	0008_index_together_recipient_unread	2026-09-12 12:06:49.00269+00
98	notifications	0009_alter_notification_options_and_more	2026-09-12 12:06:52.090559+00
99	pentest	0001_initial	2026-09-12 12:06:52.791294+00
100	pentest	0002_pentestscandb_critical_vul	2026-09-12 12:06:52.864645+00
101	pentest	0003_pentestscanresultsdb_note	2026-09-12 12:06:52.94066+00
102	pentest	0004_auto_20230506_1302	2026-09-12 12:06:55.19009+00
103	projects	0018_auto_20220826_1608	2026-09-12 12:06:56.25486+00
104	projects	0019_auto_20230506_1302	2026-09-12 12:06:59.039647+00
105	user_management	0002_rename_it_user_to_org_admin	2026-09-12 12:06:59.278642+00
106	user_management	0002_alter_userprofile_image	2026-09-12 12:06:59.431193+00
107	user_management	0003_alter_userprofile_token_time	2026-09-12 12:06:59.586357+00
108	user_management	0004_userprofile_created_time	2026-09-12 12:06:59.855676+00
109	scanners	0001_initial	2026-09-12 12:07:02.93158+00
110	scanners	0002_nvdcache	2026-09-12 12:07:02.950309+00
111	scanners	0003_auto_20260706_1434	2026-09-12 12:07:03.815733+00
112	sessions	0001_initial	2026-09-12 12:07:03.845234+00
113	sitetree	0001_initial	2026-09-12 12:07:05.028853+00
114	sitetree	0002_alter_treeitem_parent_alter_treeitem_tree	2026-09-12 12:07:05.471467+00
115	staticscanners	0001_initial	2026-09-12 12:07:05.524644+00
116	staticscanners	0002_auto_20181101_1454	2026-09-12 12:07:05.575225+00
117	staticscanners	0003_auto_20181101_1614	2026-09-12 12:07:05.672793+00
118	staticscanners	0004_dependencycheck_scan_db_dependencycheck_scan_results_db	2026-09-12 12:07:05.737928+00
119	staticscanners	0005_findbugs_scan_db_findbugs_scan_results_db	2026-09-12 12:07:05.773284+00
120	staticscanners	0006_findbugs_scan_results_db_priority	2026-09-12 12:07:05.810666+00
121	staticscanners	0007_findbugs_scan_results_db_risk	2026-09-12 12:07:05.839978+00
122	staticscanners	0008_auto_20190125_0726	2026-09-12 12:07:05.939002+00
123	staticscanners	0009_auto_20190207_0518	2026-09-12 12:07:06.303721+00
124	staticscanners	0010_clair_scan_db_clair_scan_results_db	2026-09-12 12:07:06.351148+00
125	staticscanners	0011_clair_scan_results_db_controls_tags_audit_text	2026-09-12 12:07:06.370417+00
126	staticscanners	0012_auto_20190824_0202	2026-09-12 12:07:06.437217+00
127	staticscanners	0013_trivy_scan_db_trivy_scan_results_db	2026-09-12 12:07:06.463708+00
128	staticscanners	0013_auto_20191026_0918	2026-09-12 12:07:06.480962+00
129	staticscanners	0014_merge_20191125_0532	2026-09-12 12:07:06.486935+00
130	staticscanners	0015_npmaudit_scan_db_npmaudit_scan_results_db	2026-09-12 12:07:06.524784+00
131	staticscanners	0016_nodejsscan_scan_db_nodejsscan_scan_results_db	2026-09-12 12:07:06.555956+00
132	staticscanners	0017_nodejsscan_scan_results_db_severity	2026-09-12 12:07:06.566533+00
133	staticscanners	0018_tfsec_scan_db_tfsec_scan_results_db	2026-09-12 12:07:06.596904+00
134	staticscanners	0019_auto_20200503_1201	2026-09-12 12:07:06.796214+00
135	staticscanners	0020_auto_20200715_0712	2026-09-12 12:07:06.839033+00
136	staticscanners	0021_whitesource_scan_db_whitesource_scan_results_db	2026-09-12 12:07:06.873018+00
137	staticscanners	0022_auto_20200823_1753	2026-09-12 12:07:06.925508+00
138	staticscanners	0023_checkmarx_scan_db_checkmarx_scan_results_db	2026-09-12 12:07:06.956625+00
139	staticscanners	0024_auto_20200826_1408	2026-09-12 12:07:06.991074+00
140	staticscanners	0025_gitlabsast_scan_db_gitlabsast_scan_results_db_gitlabsca_scan_db_gitlabsca_scan_results_db	2026-09-12 12:07:07.057369+00
141	staticscanners	0026_semgrepscan_scan_db_semgrepscan_scan_results_db	2026-09-12 12:07:07.111646+00
142	staticscanners	0027_gitlabcontainerscan_scan_db_gitlabcontainerscan_scan_results_db	2026-09-12 12:07:07.150751+00
143	staticscanners	0028_auto_20201004_1522	2026-09-12 12:07:07.370776+00
144	staticscanners	0029_auto_20201006_0834	2026-09-12 12:07:08.156668+00
145	staticscanners	0030_auto_20201006_0858	2026-09-12 12:07:08.690027+00
146	staticscanners	0031_auto_20201006_1432	2026-09-12 12:07:08.736186+00
147	staticscanners	0032_auto_20201006_1433	2026-09-12 12:07:08.76226+00
148	staticscanners	0033_twistlock_scan_db_twistlock_scan_results_db	2026-09-12 12:07:08.844483+00
149	staticscanners	0034_brakeman_scan_db_brakeman_scan_results_db	2026-09-12 12:07:08.939106+00
150	staticscanners	0035_auto_20210601_1830	2026-09-12 12:07:09.247328+00
151	staticscanners	0036_auto_20210719_1431	2026-09-12 12:07:10.23369+00
152	staticscanners	0037_staticscanresultsdb_note	2026-09-12 12:07:10.438237+00
153	staticscanners	0038_auto_20230506_1302	2026-09-12 12:07:12.279562+00
154	token_blacklist	0001_initial	2026-09-12 12:07:12.610155+00
155	token_blacklist	0002_outstandingtoken_jti_hex	2026-09-12 12:07:13.021379+00
156	token_blacklist	0003_auto_20171017_2007	2026-09-12 12:07:13.186691+00
157	token_blacklist	0004_auto_20171017_2013	2026-09-12 12:07:13.36297+00
158	token_blacklist	0005_remove_outstandingtoken_jti	2026-09-12 12:07:13.514966+00
159	token_blacklist	0006_auto_20171017_2113	2026-09-12 12:07:13.663976+00
160	token_blacklist	0007_auto_20171017_2214	2026-09-12 12:07:13.987748+00
161	token_blacklist	0008_migrate_to_bigautofield	2026-09-12 12:07:14.211855+00
162	token_blacklist	0010_fix_migrate_to_bigautofield	2026-09-12 12:07:14.605534+00
163	token_blacklist	0011_linearizes_history	2026-09-12 12:07:14.609453+00
164	token_blacklist	0012_alter_outstandingtoken_user	2026-09-12 12:07:14.752508+00
165	tools	0001_initial	2026-09-12 12:07:15.776322+00
166	tools	0002_auto_20230506_1302	2026-09-12 12:07:21.511228+00
167	tools	0003_add_proc_fields	2026-09-12 12:07:22.153772+00
168	user_management	0005_userprofile_notification_prefs	2026-09-12 12:07:23.567899+00
169	webscanners	0001_initial	2026-09-12 12:07:23.635505+00
170	webscanners	0002_auto_20181031_0022	2026-09-12 12:07:24.343889+00
171	webscanners	0003_auto_20190207_0331	2026-09-12 12:07:24.444025+00
172	webscanners	0004_zap_scans_db_info_vul	2026-09-12 12:07:24.463576+00
173	webscanners	0005_arachni_scan_db_info_vul	2026-09-12 12:07:24.481923+00
174	webscanners	0006_burp_scan_db_info_vul	2026-09-12 12:07:24.49888+00
175	webscanners	0007_status_db	2026-09-12 12:07:24.516944+00
176	webscanners	0008_delete_status_db	2026-09-12 12:07:24.528585+00
177	webscanners	0009_burp_issue_definitions	2026-09-12 12:07:24.548636+00
178	webscanners	0010_burp_issue_definitions_remediation	2026-09-12 12:07:24.564352+00
179	webscanners	0011_auto_20190408_1502	2026-09-12 12:07:24.963057+00
180	webscanners	0012_burp_scan_result_db_severity_color	2026-09-12 12:07:24.983791+00
181	webscanners	0013_burp_scan_result_db_path	2026-09-12 12:07:25.002164+00
182	webscanners	0014_auto_20190409_0540	2026-09-12 12:07:25.065205+00
183	webscanners	0015_burp_issue_definitions_reference	2026-09-12 12:07:25.087582+00
184	webscanners	0016_burp_issue_definitions_vulnerability_classifications	2026-09-12 12:07:25.101623+00
185	webscanners	0017_auto_20200503_1201	2026-09-12 12:07:25.350579+00
186	webscanners	0018_auto_20201004_1522	2026-09-12 12:07:25.437493+00
187	webscanners	0019_webscanresultsdb_webscansdb	2026-09-12 12:07:25.471902+00
188	webscanners	0020_auto_20210130_0530	2026-09-12 12:07:25.49336+00
189	webscanners	0021_auto_20210130_0655	2026-09-12 12:07:25.755598+00
190	webscanners	0022_auto_20210506_1634	2026-09-12 12:07:25.785183+00
191	webscanners	0023_delete_burp_scan_db	2026-09-12 12:07:25.799198+00
192	webscanners	0024_auto_20210514_1929	2026-09-12 12:07:25.875958+00
193	webscanners	0025_burp_issue_definitions	2026-09-12 12:07:25.902066+00
194	webscanners	0026_auto_20210719_1431	2026-09-12 12:07:28.054432+00
195	webscanners	0027_web_scan_db_critical_vul	2026-09-12 12:07:28.356096+00
196	webscanners	0028_webscanresultsdb_note	2026-09-12 12:07:28.653483+00
197	webscanners	0029_auto_20230506_1302	2026-09-12 12:07:36.439849+00
198	webscanners	0030_webscansdb_failure_reason	2026-09-12 12:07:36.659399+00
199	webscanners	0031_backfill_failure_reason	2026-09-12 12:07:36.906933+00
200	webscanners	0032_webscansdb_zap_ascan_id	2026-09-12 12:07:37.113606+00
201	webscanners	0033_webscansdb_scan_type	2026-09-12 12:07:37.352282+00
202	webscanners	0034_webscanresultsdb_scan_phase	2026-09-12 12:07:37.577639+00
203	webscanners	0035_backfill_scan_phase_nikto	2026-09-12 12:07:37.829298+00
204	webscanners	0036_task_schedule_fields	2026-09-12 12:07:38.979643+00
205	webscanners	0037_task_schedule_scan_config	2026-09-12 12:07:39.406185+00
206	webscanners	0038_auto_20260824_1941	2026-09-12 12:07:40.685417+00
\.


--
-- Data for Name: django_session; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.django_session (session_key, session_data, expire_date) FROM stdin;
zbrbyimb6gedborboe58t761ju4umnio	.eJxVi0sOwiAQQO_C2jQzLaXg0qTnIMPABKJiInRlvLs26UK37_NSnrae_dbS05eozgrV6ZcF4muqu9hZqr0w9fKowyHasN6p3C5H9vdmavk7ggR27IiQiFHmKTkIIzLYBIJagwgs1syL4ShiY8BRG21ZeHIcxKr3B-4KNyM:1x5MXd:MK5XdozZK5AFPmcL_t8TqTwcLRuwElRAUBRhvtTACoA	2026-09-26 12:09:09.104794+00
zwo0vx37rv0x8jqjx0yk62x3bt3uabyz	.eJxVjsEOgyAQRP-Fc2MWRYQem_gdZFlZIW0xETw1_fdq46G9zps3mZdwuNXothJWlyZxFVJcfjOPdA_5AEcWck2ENS25OUFpxiemx-2s_bkRS9xFYE-WLKJEJMl9Fyz4VhKYACyVAmYYjO4HTROzmbxslVaGmDpLns0-WkKtKc_FLev8_fj-AEXYPVo:1x5Mh7:D67jEDdMihDGSyQi6V19HDMsbOgAasUW0hRMAHw2qro	2026-09-26 12:18:57.071521+00
\.


--
-- Data for Name: docklescandb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.docklescandb (id, scan_id, rescan_id, scan_date, project_name, total_vuln, scan_status, date_time, total_dup, dockle_fatal, dockle_warn, dockle_info, dockle_pass, username, updated_time, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: docklescanresultsdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.docklescanresultsdb (id, scan_id, rescan_id, scan_date, date_time, vuln_id, false_positive, vul_col, dup_hash, vuln_duplicate, false_positive_hash, vuln_status, scanner, username, code, title, level, alerts, updated_time, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: inspecscandb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.inspecscandb (id, scan_id, rescan_id, scan_date, project_name, total_vuln, scan_status, date_time, total_dup, inspec_failed, inspec_passed, inspec_skipped, updated_time, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: inspecscanresultdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.inspecscanresultdb (id, scan_id, rescan_id, scan_date, vuln_id, date_time, false_positive, vul_col, dup_hash, vuln_duplicate, false_positive_hash, vuln_status, "Name", platform_name, platform_release, profiles_name, profiles_sha256, profiles_title, profiles_supports, attributes_name, attributes_options_description, attributes_options_default, groups_id, groups_controls, controls_id, controls_title, controls_desc, controls_descriptions, controls_impact, controls_refs, controls_tags_severity, controls_tags_cis_id, controls_tags_cis_control, controls_tags_cis_level, controls_tags_audit, controls_tags_fix, controls_tags_defaultvalue, controls_code, controls_source_location, controls_results_status, controls_results_code_desc, controls_results_run_time, controls_results_start_time, controls_results_message, controls_results_backtrace, controls_tags_audit_text, scanner, username, updated_time, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: jiraticketing_jirasetting; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.jiraticketing_jirasetting (id, setting_id, jira_server, jira_username, jira_password, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
1	708b1be3-1a5d-4d2b-8ec4-9ae008b6698a	https://my-fyp-org.atlassian.net	InRwMDc3OTI4QG1haWwuYXB1LmVkdS5teSI:1x5Mel:4lhb3UIuXtplew9S8Gym44Ilwih1jw57JONexTpwfns	IkFUQVRUM3hGZkdGMHcxa0pXcmtNZ09QcjhwTmlBdFFmSXBtOVRTZ0RMT2h1YXVEMnBhWVpEcTQ4WDk1YkVrcFd2bFZFTmp6NFdoZW1SLXhqUnpIX1BLNHBqR00zVkVaYThWdElVMmJjS3QxaEJZQ1d4X3ZqMV9IQmt0MUM1dG90NDAyYTZHRVVsZ3Qxd1M1b0V5SVNubmYzQXM4X2hZdzhFalBLNlZsNUR5b3JlVDFaaGtuVHlncz05N0Y5OTk0QiI:1x5Mel:V5-A1VdAjMpOczXFySRP7FV3qUtCY1zdOUu1zIZkCxU	\N	2026-09-12 12:16:31.284787+00	t	1	\N
\.


--
-- Data for Name: monthdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.monthdb (id, month, high, medium, low, updated_time, project_id, critical, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
1		0	0	0	2026-09-12 12:18:13.627151+00	1	0	\N	2026-09-12 12:18:13.627182+00	t	1	\N
\.


--
-- Data for Name: networkscandb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.networkscandb (id, scan_id, ip, rescan_id, scan_date, scan_status, total_vul, critical_vul, high_vul, medium_vul, low_vul, info_vul, date_time, rescan, total_dup, scanner, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id, failure_reason, updated_time, scan_type, runner_pid) FROM stdin;
\.


--
-- Data for Name: networkscanresultsdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.networkscanresultsdb (id, scan_id, vuln_id, title, date_time, severity_color, severity, description, solution, port, ip, scanner, jira_ticket, dup_hash, vuln_duplicate, false_positive, vuln_status, false_positive_hash, project_id, updated_time, note, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: notifications_notification; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.notifications_notification (id, level, unread, actor_object_id, verb, description, target_object_id, action_object_object_id, "timestamp", public, action_object_content_type_id, actor_content_type_id, recipient_id, target_content_type_id, deleted, emailed, data) FROM stdin;
\.


--
-- Data for Name: nvd_cache; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.nvd_cache (cve_id, cvss_score, cvss_severity, cvss_vector, description, "references", source, fetched_at) FROM stdin;
\.


--
-- Data for Name: org_apikey; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.org_apikey (id, uu_id, api_key, created_time, is_active, created_by_id, name, organization_id) FROM stdin;
\.


--
-- Data for Name: organization; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.organization (id, uu_id, name, description, logo, contact, token_time, address) FROM stdin;
1	16a1ec61-e99b-473b-b10b-ed4edab4aa7f	default	Default Organization	default_logo		2026-09-12 12:08:18.401178+00	default
\.


--
-- Data for Name: pentest_pentestscandb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.pentest_pentestscandb (id, scan_url, scan_id, total_vul, high_vul, medium_vul, low_vul, date_time, pentest_type, project_id, critical_vul, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: pentest_pentestscanresultsdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.pentest_pentestscanresultsdb (id, vuln_id, scan_id, date_time, rescan_id, vuln_name, severity, severity_color, vuln_url, scan_url, description, solution, request_header, response_header, reference, vuln_status, "Poc_Img", poc_description, pentest_type, project_id, note, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: pentest_vulnerabilitydata; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.pentest_vulnerabilitydata (id, vuln_data_id, vuln_name, vuln_description, vuln_severity, vuln_remediation, vuln_references, date_time, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: project; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.project (id, uu_id, project_name, project_start, project_end, project_owner, project_disc, project_status, date_time, total_vuln, total_high, total_medium, total_low, total_open, total_false, total_close, total_net, total_web, total_static, high_net, high_web, high_static, medium_net, medium_web, medium_static, low_net, low_web, low_static, created_time, updated_time, is_active, created_by_id, updated_by_id, critical_net, critical_static, critical_web, total_critical, critical_cloud, high_cloud, low_cloud, medium_cloud, total_cloud, organization_id) FROM stdin;
1	03915f94-0eff-4ce8-b073-25150f3fdf65	Demo Verify Project			immah@gmail.com	FYP demo verification	Open	\N	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	2026-09-12 12:17:02.910535+00	2026-09-12 12:17:02.910584+00	t	1	\N	0	0	0	0	0	0	0	0	0	1
\.


--
-- Data for Name: projectscandb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.projectscandb (id, project_url, project_ip, scan_type, date_time, updated_time, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: sitetree_tree; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.sitetree_tree (id, title, alias) FROM stdin;
\.


--
-- Data for Name: sitetree_treeitem; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.sitetree_treeitem (id, title, hint, url, urlaspattern, hidden, alias, description, inmenu, inbreadcrumbs, insitetree, access_loggedin, access_guest, access_restricted, access_perm_type, sort_order, parent_id, tree_id) FROM stdin;
\.


--
-- Data for Name: sitetree_treeitem_access_permissions; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.sitetree_treeitem_access_permissions (id, treeitem_id, permission_id) FROM stdin;
\.


--
-- Data for Name: staticscanresultsdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.staticscanresultsdb (id, scan_id, rescan_id, date_time, vuln_id, false_positive, severity_color, dup_hash, vuln_duplicate, false_positive_hash, vuln_status, jira_ticket, title, severity, description, "references", "fileName", "filePath", solution, scanner, project_id, updated_time, note, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: staticscansdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.staticscansdb (id, project_name, scan_id, rescan_id, scan_date, scan_status, total_vul, critical_vul, high_vul, medium_vul, low_vul, info_vul, date_time, rescan, total_dup, scanner, project_id, updated_time, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: taskscheduledb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.taskscheduledb (id, task_id, target, schedule_time, project_id, scanner, periodic_task, updated_time, created_by_id, created_time, is_active, organization_id, updated_by_id, last_run_at, schedule_time_utc, scan_config, scan_type) FROM stdin;
\.


--
-- Data for Name: token_blacklist_blacklistedtoken; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.token_blacklist_blacklistedtoken (id, blacklisted_at, token_id) FROM stdin;
\.


--
-- Data for Name: token_blacklist_outstandingtoken; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.token_blacklist_outstandingtoken (id, token, created_at, expires_at, user_id, jti) FROM stdin;
\.


--
-- Data for Name: tools_niktoresultdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.tools_niktoresultdb (id, scan_id, scan_url, nikto_scan_output, date_time, nikto_status, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id, pid, pgid) FROM stdin;
\.


--
-- Data for Name: tools_niktovulndb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.tools_niktovulndb (id, vuln_id, scan_id, scan_url, discription, targetip, hostname, port, uri, httpmethod, testlinks, osvdb, false_positive, jira_ticket, vuln_status, dup_hash, vuln_duplicate, false_positive_hash, date_time, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: tools_nmapresultdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.tools_nmapresultdb (id, scan_id, ip_address, protocol, port, state, reason, reason_ttl, version, extrainfo, name, conf, method, type_p, osfamily, vendor, osgen, accuracy, cpe, used_state, used_portid, used_proto, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: tools_nmapscandb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.tools_nmapscandb (id, scan_id, scan_ip, total_ports, total_open_ports, total_close_ports, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id, pid, pgid) FROM stdin;
\.


--
-- Data for Name: tools_nmapvulnersportresultdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.tools_nmapvulnersportresultdb (nmapresultdb_ptr_id, vulners_extrainfo) FROM stdin;
\.


--
-- Data for Name: tools_sslscanresultdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.tools_sslscanresultdb (id, scan_id, scan_url, sslscan_output, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: unified_scan_config; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.unified_scan_config (scan_id, scan_type, scanner_name, target, targets, profile, options, timeout, schedule_config, schedule_type, created_at, updated_at, created_by_id, organization_id, project_id) FROM stdin;
\.


--
-- Data for Name: unified_scan_result; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.unified_scan_result (scan_id, result_id, scan_type, scanner_name, target, vulnerability, title, description, solution, severity, cvss_score, cvss_vector, cwe_id, cve_id, url, host, port, path, parameter, method, evidence, request, response, payload, dup_hash, false_positive, duplicate, vuln_status, "references", tags, scan_status, started_at, completed_at, failure_reason, created_at, updated_at, created_by_id, organization_id, project_id) FROM stdin;
\.


--
-- Data for Name: unified_scan_summary; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.unified_scan_summary (scan_id, scan_type, scanner_name, target, total_vulns, critical_count, high_count, medium_count, low_count, info_count, unknown_count, scan_status, started_at, completed_at, failure_reason, created_at, updated_at, created_by_id, organization_id, project_id) FROM stdin;
\.


--
-- Data for Name: user_login_history; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.user_login_history (id, logintime, logouttime, "IP", user_id) FROM stdin;
\.


--
-- Data for Name: user_profile; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.user_profile (id, password, last_login, is_superuser, email, name, image, is_active, is_staff, uu_id, pass_token, token_time, password_updt_time, organization_id, role_id, created_time, notify_critical_only, notify_email, notify_in_app, notify_on_scan_complete, notify_on_scan_fail, notify_on_scan_start) FROM stdin;
1	pbkdf2_sha256$260000$2RULYD4hWeRstrF4ulVutx$azC6ClT8PsS10O1E2CCP4MWiqZ1EKJ1gBwUisIzo/TE=	2026-09-12 12:16:31.153609+00	t	immah@gmail.com	Teamcloud		t	t	0e9f8ae7-5be5-4ef1-a003-96e194903f99	\N	\N	2026-09-12 12:08:18.83103+00	1	4	2026-09-12 12:08:18.76685+00	f	t	t	t	t	f
\.


--
-- Data for Name: user_profile_groups; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.user_profile_groups (id, userprofile_id, group_id) FROM stdin;
\.


--
-- Data for Name: user_profile_user_permissions; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.user_profile_user_permissions (id, userprofile_id, permission_id) FROM stdin;
\.


--
-- Data for Name: user_roles; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.user_roles (id, role, description, uu_id) FROM stdin;
1	Admin	Admin can manage organization level site	cee499a2-9273-4733-991b-4b96338a845f
2	Analyst	Analyst can create scannings	40a84902-719c-46e3-b699-bd39f8a6f360
3	Viewer	Viewers can only view dashboards	6df7ffbf-0c94-416f-abea-ecccfe91e20e
4	Organization Admin	Can manage users and settings within their organization	574e3e5c-53d5-4197-9377-133b6d9338ad
\.


--
-- Data for Name: webscanResultsdb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public."webscanResultsdb" (id, vuln_id, scan_id, rescan_id, url, title, solution, description, severity_color, severity, date_time, false_positive, jira_ticket, vuln_status, dup_hash, vuln_duplicate, false_positive_hash, scanner, instance, reference, project_id, updated_time, note, created_by_id, created_time, is_active, organization_id, updated_by_id, scan_phase, cvss_score, mitre_techniques, risk_score) FROM stdin;
\.


--
-- Data for Name: webscandb; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.webscandb (id, scan_url, scan_id, rescan_id, scan_date, scan_status, total_vul, critical_vul, high_vul, medium_vul, low_vul, info_vul, date_time, rescan, total_dup, scanner, project_id, updated_time, created_by_id, created_time, is_active, organization_id, updated_by_id, failure_reason, zap_ascan_id, scan_type) FROM stdin;
\.


--
-- Data for Name: webscanners_burp_issue_definitions; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.webscanners_burp_issue_definitions (id, remediation, issue_type_id, description, reference, vulnerability_classifications, name, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: webscanners_cookie_db; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.webscanners_cookie_db (id, url, cookie) FROM stdin;
\.


--
-- Data for Name: webscanners_email_config_db; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.webscanners_email_config_db (id, email_id_from, email_subject, email_message, email_id_to, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: webscanners_excluded_db; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.webscanners_excluded_db (id, exclude_url) FROM stdin;
\.


--
-- Data for Name: webscanners_task_schedule_db; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.webscanners_task_schedule_db (id, task_id, target, schedule_time, scanner, periodic_task, project_id, created_by_id, created_time, is_active, organization_id, updated_by_id, last_run_at, schedule_time_utc, scan_config, scan_type) FROM stdin;
\.


--
-- Data for Name: webscanners_web_scan_db; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.webscanners_web_scan_db (id, scan_url, scan_id, scan_date, scan_status, total_vul, high_vul, medium_vul, low_vul, info_vuln, scanner, project_id, critical_vul, created_by_id, created_time, is_active, organization_id, updated_by_id) FROM stdin;
\.


--
-- Data for Name: webscanners_zap_spider_db; Type: TABLE DATA; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

COPY public.webscanners_zap_spider_db (id, spider_url, spider_scanid, urls_num) FROM stdin;
\.


--
-- Name: archerysettings_arachnisettingsdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.archerysettings_arachnisettingsdb_id_seq', 1, false);


--
-- Name: archerysettings_burpsettingdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.archerysettings_burpsettingdb_id_seq', 1, false);


--
-- Name: archerysettings_emaildb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.archerysettings_emaildb_id_seq', 1, true);


--
-- Name: archerysettings_niktosettingdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.archerysettings_niktosettingdb_id_seq', 1, true);


--
-- Name: archerysettings_nmapsettingdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.archerysettings_nmapsettingdb_id_seq', 1, true);


--
-- Name: archerysettings_nmapvulnerssettingdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.archerysettings_nmapvulnerssettingdb_id_seq', 1, false);


--
-- Name: archerysettings_openvassettingdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.archerysettings_openvassettingdb_id_seq', 1, true);


--
-- Name: archerysettings_settingsdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.archerysettings_settingsdb_id_seq', 6, true);


--
-- Name: archerysettings_zapsettingsdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.archerysettings_zapsettingsdb_id_seq', 1, true);


--
-- Name: auth_group_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.auth_group_id_seq', 1, false);


--
-- Name: auth_group_permissions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.auth_group_permissions_id_seq', 1, false);


--
-- Name: auth_permission_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.auth_permission_id_seq', 264, true);


--
-- Name: cicd_scannercommand_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.cicd_scannercommand_id_seq', 1, false);


--
-- Name: cicddb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.cicddb_id_seq', 1, false);


--
-- Name: cloudscansdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.cloudscansdb_id_seq', 1, false);


--
-- Name: cloudscansresultsdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.cloudscansresultsdb_id_seq', 1, false);


--
-- Name: django_admin_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.django_admin_log_id_seq', 1, false);


--
-- Name: django_content_type_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.django_content_type_id_seq', 66, true);


--
-- Name: django_migrations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.django_migrations_id_seq', 206, true);


--
-- Name: docklescandb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.docklescandb_id_seq', 1, false);


--
-- Name: docklescanresultsdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.docklescanresultsdb_id_seq', 1, false);


--
-- Name: inspecscandb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.inspecscandb_id_seq', 1, false);


--
-- Name: inspecscanresultdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.inspecscanresultdb_id_seq', 1, false);


--
-- Name: jiraticketing_jirasetting_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.jiraticketing_jirasetting_id_seq', 1, true);


--
-- Name: monthdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.monthdb_id_seq', 1, true);


--
-- Name: networkscanners_networkscandb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.networkscanners_networkscandb_id_seq', 1, false);


--
-- Name: networkscanners_networkscanresultsdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.networkscanners_networkscanresultsdb_id_seq', 1, false);


--
-- Name: notifications_notification_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.notifications_notification_id_seq', 1, false);


--
-- Name: org_apikey_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.org_apikey_id_seq', 1, false);


--
-- Name: organization_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.organization_id_seq', 1, true);


--
-- Name: pentest_pentestscandb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.pentest_pentestscandb_id_seq', 1, false);


--
-- Name: pentest_pentestscanresultsdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.pentest_pentestscanresultsdb_id_seq', 1, false);


--
-- Name: pentest_vulnerabilitydata_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.pentest_vulnerabilitydata_id_seq', 1, false);


--
-- Name: project_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.project_id_seq', 1, true);


--
-- Name: projectscandb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.projectscandb_id_seq', 1, false);


--
-- Name: sitetree_tree_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.sitetree_tree_id_seq', 1, false);


--
-- Name: sitetree_treeitem_access_permissions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.sitetree_treeitem_access_permissions_id_seq', 1, false);


--
-- Name: sitetree_treeitem_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.sitetree_treeitem_id_seq', 1, false);


--
-- Name: staticscanners_staticscanresultsdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.staticscanners_staticscanresultsdb_id_seq', 1, false);


--
-- Name: staticscanners_staticscansdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.staticscanners_staticscansdb_id_seq', 1, false);


--
-- Name: taskscheduledb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.taskscheduledb_id_seq', 1, false);


--
-- Name: token_blacklist_blacklistedtoken_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.token_blacklist_blacklistedtoken_id_seq', 1, false);


--
-- Name: token_blacklist_outstandingtoken_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.token_blacklist_outstandingtoken_id_seq', 1, false);


--
-- Name: tools_niktoresultdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.tools_niktoresultdb_id_seq', 1, false);


--
-- Name: tools_niktovulndb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.tools_niktovulndb_id_seq', 1, false);


--
-- Name: tools_nmapresultdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.tools_nmapresultdb_id_seq', 1, false);


--
-- Name: tools_nmapscandb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.tools_nmapscandb_id_seq', 1, false);


--
-- Name: tools_sslscanresultdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.tools_sslscanresultdb_id_seq', 1, false);


--
-- Name: user_login_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.user_login_history_id_seq', 1, false);


--
-- Name: user_profile_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.user_profile_groups_id_seq', 1, false);


--
-- Name: user_profile_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.user_profile_id_seq', 1, true);


--
-- Name: user_profile_user_permissions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.user_profile_user_permissions_id_seq', 1, false);


--
-- Name: user_roles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.user_roles_id_seq', 4, true);


--
-- Name: webscanners_burp_issue_definitions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.webscanners_burp_issue_definitions_id_seq', 1, false);


--
-- Name: webscanners_cookie_db_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.webscanners_cookie_db_id_seq', 1, false);


--
-- Name: webscanners_email_config_db_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.webscanners_email_config_db_id_seq', 1, false);


--
-- Name: webscanners_excluded_db_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.webscanners_excluded_db_id_seq', 1, false);


--
-- Name: webscanners_task_schedule_db_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.webscanners_task_schedule_db_id_seq', 1, false);


--
-- Name: webscanners_web_scan_db_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.webscanners_web_scan_db_id_seq', 1, false);


--
-- Name: webscanners_webscanresultsdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.webscanners_webscanresultsdb_id_seq', 1, false);


--
-- Name: webscanners_webscansdb_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.webscanners_webscansdb_id_seq', 1, false);


--
-- Name: webscanners_zap_spider_db_id_seq; Type: SEQUENCE SET; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

SELECT pg_catalog.setval('public.webscanners_zap_spider_db_id_seq', 1, false);


--
-- Name: archerysettings_arachnisettingsdb archerysettings_arachnisettingsdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_arachnisettingsdb
    ADD CONSTRAINT archerysettings_arachnisettingsdb_pkey PRIMARY KEY (id);


--
-- Name: archerysettings_burpsettingdb archerysettings_burpsettingdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_burpsettingdb
    ADD CONSTRAINT archerysettings_burpsettingdb_pkey PRIMARY KEY (id);


--
-- Name: archerysettings_emaildb archerysettings_emaildb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_emaildb
    ADD CONSTRAINT archerysettings_emaildb_pkey PRIMARY KEY (id);


--
-- Name: archerysettings_niktosettingdb archerysettings_niktosettingdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_niktosettingdb
    ADD CONSTRAINT archerysettings_niktosettingdb_pkey PRIMARY KEY (id);


--
-- Name: archerysettings_nmapsettingdb archerysettings_nmapsettingdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapsettingdb
    ADD CONSTRAINT archerysettings_nmapsettingdb_pkey PRIMARY KEY (id);


--
-- Name: archerysettings_nmapvulnerssettingdb archerysettings_nmapvulnerssettingdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapvulnerssettingdb
    ADD CONSTRAINT archerysettings_nmapvulnerssettingdb_pkey PRIMARY KEY (id);


--
-- Name: archerysettings_openvassettingdb archerysettings_openvassettingdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_openvassettingdb
    ADD CONSTRAINT archerysettings_openvassettingdb_pkey PRIMARY KEY (id);


--
-- Name: archerysettings_settingsdb archerysettings_settingsdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_settingsdb
    ADD CONSTRAINT archerysettings_settingsdb_pkey PRIMARY KEY (id);


--
-- Name: archerysettings_zapsettingsdb archerysettings_zapsettingsdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_zapsettingsdb
    ADD CONSTRAINT archerysettings_zapsettingsdb_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: auth_group auth_group_name_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_name_key UNIQUE (name);


--
-- Name: auth_group_permissions auth_group_permissions_group_id_permission_id_0cd325b0_uniq; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_group_id_permission_id_0cd325b0_uniq UNIQUE (group_id, permission_id);


--
-- Name: auth_group_permissions auth_group_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_pkey PRIMARY KEY (id);


--
-- Name: auth_group auth_group_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_pkey PRIMARY KEY (id);


--
-- Name: auth_permission auth_permission_content_type_id_codename_01ab375a_uniq; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_content_type_id_codename_01ab375a_uniq UNIQUE (content_type_id, codename);


--
-- Name: auth_permission auth_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_pkey PRIMARY KEY (id);


--
-- Name: authtoken_token authtoken_token_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.authtoken_token
    ADD CONSTRAINT authtoken_token_pkey PRIMARY KEY (key);


--
-- Name: authtoken_token authtoken_token_user_id_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.authtoken_token
    ADD CONSTRAINT authtoken_token_user_id_key UNIQUE (user_id);


--
-- Name: cicd_scannercommand cicd_scannercommand_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicd_scannercommand
    ADD CONSTRAINT cicd_scannercommand_pkey PRIMARY KEY (id);


--
-- Name: cicddb cicddb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicddb
    ADD CONSTRAINT cicddb_pkey PRIMARY KEY (id);


--
-- Name: cloudscansdb cloudscansdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansdb
    ADD CONSTRAINT cloudscansdb_pkey PRIMARY KEY (id);


--
-- Name: cloudscansresultsdb cloudscansresultsdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansresultsdb
    ADD CONSTRAINT cloudscansresultsdb_pkey PRIMARY KEY (id);


--
-- Name: django_admin_log django_admin_log_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_pkey PRIMARY KEY (id);


--
-- Name: django_content_type django_content_type_app_label_model_76bd3d3b_uniq; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_content_type
    ADD CONSTRAINT django_content_type_app_label_model_76bd3d3b_uniq UNIQUE (app_label, model);


--
-- Name: django_content_type django_content_type_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_content_type
    ADD CONSTRAINT django_content_type_pkey PRIMARY KEY (id);


--
-- Name: django_migrations django_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_migrations
    ADD CONSTRAINT django_migrations_pkey PRIMARY KEY (id);


--
-- Name: django_session django_session_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_session
    ADD CONSTRAINT django_session_pkey PRIMARY KEY (session_key);


--
-- Name: docklescandb docklescandb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescandb
    ADD CONSTRAINT docklescandb_pkey PRIMARY KEY (id);


--
-- Name: docklescanresultsdb docklescanresultsdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescanresultsdb
    ADD CONSTRAINT docklescanresultsdb_pkey PRIMARY KEY (id);


--
-- Name: inspecscandb inspecscandb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscandb
    ADD CONSTRAINT inspecscandb_pkey PRIMARY KEY (id);


--
-- Name: inspecscanresultdb inspecscanresultdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscanresultdb
    ADD CONSTRAINT inspecscanresultdb_pkey PRIMARY KEY (id);


--
-- Name: jiraticketing_jirasetting jiraticketing_jirasetting_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.jiraticketing_jirasetting
    ADD CONSTRAINT jiraticketing_jirasetting_pkey PRIMARY KEY (id);


--
-- Name: monthdb monthdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.monthdb
    ADD CONSTRAINT monthdb_pkey PRIMARY KEY (id);


--
-- Name: networkscandb networkscanners_networkscandb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscandb
    ADD CONSTRAINT networkscanners_networkscandb_pkey PRIMARY KEY (id);


--
-- Name: networkscanresultsdb networkscanners_networkscanresultsdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscanresultsdb
    ADD CONSTRAINT networkscanners_networkscanresultsdb_pkey PRIMARY KEY (id);


--
-- Name: notifications_notification notifications_notification_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.notifications_notification
    ADD CONSTRAINT notifications_notification_pkey PRIMARY KEY (id);


--
-- Name: nvd_cache nvd_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.nvd_cache
    ADD CONSTRAINT nvd_cache_pkey PRIMARY KEY (cve_id);


--
-- Name: org_apikey org_apikey_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.org_apikey
    ADD CONSTRAINT org_apikey_pkey PRIMARY KEY (id);


--
-- Name: org_apikey org_apikey_uu_id_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.org_apikey
    ADD CONSTRAINT org_apikey_uu_id_key UNIQUE (uu_id);


--
-- Name: organization organization_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.organization
    ADD CONSTRAINT organization_pkey PRIMARY KEY (id);


--
-- Name: organization organization_uu_id_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.organization
    ADD CONSTRAINT organization_uu_id_key UNIQUE (uu_id);


--
-- Name: pentest_pentestscandb pentest_pentestscandb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscandb
    ADD CONSTRAINT pentest_pentestscandb_pkey PRIMARY KEY (id);


--
-- Name: pentest_pentestscanresultsdb pentest_pentestscanresultsdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscanresultsdb
    ADD CONSTRAINT pentest_pentestscanresultsdb_pkey PRIMARY KEY (id);


--
-- Name: pentest_vulnerabilitydata pentest_vulnerabilitydata_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_vulnerabilitydata
    ADD CONSTRAINT pentest_vulnerabilitydata_pkey PRIMARY KEY (id);


--
-- Name: project project_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.project
    ADD CONSTRAINT project_pkey PRIMARY KEY (id);


--
-- Name: project project_uu_id_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.project
    ADD CONSTRAINT project_uu_id_key UNIQUE (uu_id);


--
-- Name: projectscandb projectscandb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.projectscandb
    ADD CONSTRAINT projectscandb_pkey PRIMARY KEY (id);


--
-- Name: sitetree_tree sitetree_tree_alias_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_tree
    ADD CONSTRAINT sitetree_tree_alias_key UNIQUE (alias);


--
-- Name: sitetree_tree sitetree_tree_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_tree
    ADD CONSTRAINT sitetree_tree_pkey PRIMARY KEY (id);


--
-- Name: sitetree_treeitem_access_permissions sitetree_treeitem_access_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem_access_permissions
    ADD CONSTRAINT sitetree_treeitem_access_permissions_pkey PRIMARY KEY (id);


--
-- Name: sitetree_treeitem_access_permissions sitetree_treeitem_access_treeitem_id_permission_i_a3224a96_uniq; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem_access_permissions
    ADD CONSTRAINT sitetree_treeitem_access_treeitem_id_permission_i_a3224a96_uniq UNIQUE (treeitem_id, permission_id);


--
-- Name: sitetree_treeitem sitetree_treeitem_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem
    ADD CONSTRAINT sitetree_treeitem_pkey PRIMARY KEY (id);


--
-- Name: sitetree_treeitem sitetree_treeitem_tree_id_alias_f597fbd9_uniq; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem
    ADD CONSTRAINT sitetree_treeitem_tree_id_alias_f597fbd9_uniq UNIQUE (tree_id, alias);


--
-- Name: staticscanresultsdb staticscanners_staticscanresultsdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscanresultsdb
    ADD CONSTRAINT staticscanners_staticscanresultsdb_pkey PRIMARY KEY (id);


--
-- Name: staticscansdb staticscanners_staticscansdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscansdb
    ADD CONSTRAINT staticscanners_staticscansdb_pkey PRIMARY KEY (id);


--
-- Name: taskscheduledb taskscheduledb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.taskscheduledb
    ADD CONSTRAINT taskscheduledb_pkey PRIMARY KEY (id);


--
-- Name: token_blacklist_blacklistedtoken token_blacklist_blacklistedtoken_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.token_blacklist_blacklistedtoken
    ADD CONSTRAINT token_blacklist_blacklistedtoken_pkey PRIMARY KEY (id);


--
-- Name: token_blacklist_blacklistedtoken token_blacklist_blacklistedtoken_token_id_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.token_blacklist_blacklistedtoken
    ADD CONSTRAINT token_blacklist_blacklistedtoken_token_id_key UNIQUE (token_id);


--
-- Name: token_blacklist_outstandingtoken token_blacklist_outstandingtoken_jti_hex_d9bdf6f7_uniq; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.token_blacklist_outstandingtoken
    ADD CONSTRAINT token_blacklist_outstandingtoken_jti_hex_d9bdf6f7_uniq UNIQUE (jti);


--
-- Name: token_blacklist_outstandingtoken token_blacklist_outstandingtoken_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.token_blacklist_outstandingtoken
    ADD CONSTRAINT token_blacklist_outstandingtoken_pkey PRIMARY KEY (id);


--
-- Name: tools_niktoresultdb tools_niktoresultdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktoresultdb
    ADD CONSTRAINT tools_niktoresultdb_pkey PRIMARY KEY (id);


--
-- Name: tools_niktovulndb tools_niktovulndb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktovulndb
    ADD CONSTRAINT tools_niktovulndb_pkey PRIMARY KEY (id);


--
-- Name: tools_nmapresultdb tools_nmapresultdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapresultdb
    ADD CONSTRAINT tools_nmapresultdb_pkey PRIMARY KEY (id);


--
-- Name: tools_nmapscandb tools_nmapscandb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapscandb
    ADD CONSTRAINT tools_nmapscandb_pkey PRIMARY KEY (id);


--
-- Name: tools_nmapvulnersportresultdb tools_nmapvulnersportresultdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapvulnersportresultdb
    ADD CONSTRAINT tools_nmapvulnersportresultdb_pkey PRIMARY KEY (nmapresultdb_ptr_id);


--
-- Name: tools_sslscanresultdb tools_sslscanresultdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_sslscanresultdb
    ADD CONSTRAINT tools_sslscanresultdb_pkey PRIMARY KEY (id);


--
-- Name: unified_scan_config unified_scan_config_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_config
    ADD CONSTRAINT unified_scan_config_pkey PRIMARY KEY (scan_id);


--
-- Name: unified_scan_result unified_scan_result_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_result
    ADD CONSTRAINT unified_scan_result_pkey PRIMARY KEY (result_id);


--
-- Name: unified_scan_result unified_scan_result_scan_id_result_id_5c3dc67c_uniq; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_result
    ADD CONSTRAINT unified_scan_result_scan_id_result_id_5c3dc67c_uniq UNIQUE (scan_id, result_id);


--
-- Name: unified_scan_summary unified_scan_summary_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_summary
    ADD CONSTRAINT unified_scan_summary_pkey PRIMARY KEY (scan_id);


--
-- Name: user_login_history user_login_history_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_login_history
    ADD CONSTRAINT user_login_history_pkey PRIMARY KEY (id);


--
-- Name: user_profile user_profile_email_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile
    ADD CONSTRAINT user_profile_email_key UNIQUE (email);


--
-- Name: user_profile_groups user_profile_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_groups
    ADD CONSTRAINT user_profile_groups_pkey PRIMARY KEY (id);


--
-- Name: user_profile_groups user_profile_groups_userprofile_id_group_id_634d6ad7_uniq; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_groups
    ADD CONSTRAINT user_profile_groups_userprofile_id_group_id_634d6ad7_uniq UNIQUE (userprofile_id, group_id);


--
-- Name: user_profile user_profile_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile
    ADD CONSTRAINT user_profile_pkey PRIMARY KEY (id);


--
-- Name: user_profile_user_permissions user_profile_user_permis_userprofile_id_permissio_881e08f1_uniq; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_user_permissions
    ADD CONSTRAINT user_profile_user_permis_userprofile_id_permissio_881e08f1_uniq UNIQUE (userprofile_id, permission_id);


--
-- Name: user_profile_user_permissions user_profile_user_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_user_permissions
    ADD CONSTRAINT user_profile_user_permissions_pkey PRIMARY KEY (id);


--
-- Name: user_profile user_profile_uu_id_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile
    ADD CONSTRAINT user_profile_uu_id_key UNIQUE (uu_id);


--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (id);


--
-- Name: user_roles user_roles_role_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_role_key UNIQUE (role);


--
-- Name: user_roles user_roles_uu_id_key; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_uu_id_key UNIQUE (uu_id);


--
-- Name: webscanners_burp_issue_definitions webscanners_burp_issue_definitions_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_burp_issue_definitions
    ADD CONSTRAINT webscanners_burp_issue_definitions_pkey PRIMARY KEY (id);


--
-- Name: webscanners_cookie_db webscanners_cookie_db_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_cookie_db
    ADD CONSTRAINT webscanners_cookie_db_pkey PRIMARY KEY (id);


--
-- Name: webscanners_email_config_db webscanners_email_config_db_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_email_config_db
    ADD CONSTRAINT webscanners_email_config_db_pkey PRIMARY KEY (id);


--
-- Name: webscanners_excluded_db webscanners_excluded_db_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_excluded_db
    ADD CONSTRAINT webscanners_excluded_db_pkey PRIMARY KEY (id);


--
-- Name: webscanners_task_schedule_db webscanners_task_schedule_db_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_task_schedule_db
    ADD CONSTRAINT webscanners_task_schedule_db_pkey PRIMARY KEY (id);


--
-- Name: webscanners_web_scan_db webscanners_web_scan_db_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_web_scan_db
    ADD CONSTRAINT webscanners_web_scan_db_pkey PRIMARY KEY (id);


--
-- Name: webscanResultsdb webscanners_webscanresultsdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public."webscanResultsdb"
    ADD CONSTRAINT webscanners_webscanresultsdb_pkey PRIMARY KEY (id);


--
-- Name: webscandb webscanners_webscansdb_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscandb
    ADD CONSTRAINT webscanners_webscansdb_pkey PRIMARY KEY (id);


--
-- Name: webscanners_zap_spider_db webscanners_zap_spider_db_pkey; Type: CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_zap_spider_db
    ADD CONSTRAINT webscanners_zap_spider_db_pkey PRIMARY KEY (id);


--
-- Name: archerysettings_arachnisettingsdb_created_by_id_a8df6663; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_arachnisettingsdb_created_by_id_a8df6663 ON public.archerysettings_arachnisettingsdb USING btree (created_by_id);


--
-- Name: archerysettings_arachnisettingsdb_organization_id_0f8a5748; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_arachnisettingsdb_organization_id_0f8a5748 ON public.archerysettings_arachnisettingsdb USING btree (organization_id);


--
-- Name: archerysettings_arachnisettingsdb_updated_by_id_43478b8a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_arachnisettingsdb_updated_by_id_43478b8a ON public.archerysettings_arachnisettingsdb USING btree (updated_by_id);


--
-- Name: archerysettings_burpsettingdb_created_by_id_3a9630f1; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_burpsettingdb_created_by_id_3a9630f1 ON public.archerysettings_burpsettingdb USING btree (created_by_id);


--
-- Name: archerysettings_burpsettingdb_organization_id_a2c1c614; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_burpsettingdb_organization_id_a2c1c614 ON public.archerysettings_burpsettingdb USING btree (organization_id);


--
-- Name: archerysettings_burpsettingdb_updated_by_id_115f4907; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_burpsettingdb_updated_by_id_115f4907 ON public.archerysettings_burpsettingdb USING btree (updated_by_id);


--
-- Name: archerysettings_emaildb_created_by_id_5b4b004d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_emaildb_created_by_id_5b4b004d ON public.archerysettings_emaildb USING btree (created_by_id);


--
-- Name: archerysettings_emaildb_organization_id_801012dc; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_emaildb_organization_id_801012dc ON public.archerysettings_emaildb USING btree (organization_id);


--
-- Name: archerysettings_emaildb_updated_by_id_87e13d8d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_emaildb_updated_by_id_87e13d8d ON public.archerysettings_emaildb USING btree (updated_by_id);


--
-- Name: archerysettings_niktosettingdb_created_by_id_fd0214e2; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_niktosettingdb_created_by_id_fd0214e2 ON public.archerysettings_niktosettingdb USING btree (created_by_id);


--
-- Name: archerysettings_niktosettingdb_organization_id_c1bbbecd; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_niktosettingdb_organization_id_c1bbbecd ON public.archerysettings_niktosettingdb USING btree (organization_id);


--
-- Name: archerysettings_niktosettingdb_updated_by_id_f8c81e81; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_niktosettingdb_updated_by_id_f8c81e81 ON public.archerysettings_niktosettingdb USING btree (updated_by_id);


--
-- Name: archerysettings_nmapsettingdb_created_by_id_7a7dc24f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_nmapsettingdb_created_by_id_7a7dc24f ON public.archerysettings_nmapsettingdb USING btree (created_by_id);


--
-- Name: archerysettings_nmapsettingdb_organization_id_41937d18; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_nmapsettingdb_organization_id_41937d18 ON public.archerysettings_nmapsettingdb USING btree (organization_id);


--
-- Name: archerysettings_nmapsettingdb_updated_by_id_d727d8d8; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_nmapsettingdb_updated_by_id_d727d8d8 ON public.archerysettings_nmapsettingdb USING btree (updated_by_id);


--
-- Name: archerysettings_nmapvulnerssettingdb_created_by_id_ad9313ae; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_nmapvulnerssettingdb_created_by_id_ad9313ae ON public.archerysettings_nmapvulnerssettingdb USING btree (created_by_id);


--
-- Name: archerysettings_nmapvulnerssettingdb_organization_id_d54b54e1; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_nmapvulnerssettingdb_organization_id_d54b54e1 ON public.archerysettings_nmapvulnerssettingdb USING btree (organization_id);


--
-- Name: archerysettings_nmapvulnerssettingdb_updated_by_id_1cf83f3e; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_nmapvulnerssettingdb_updated_by_id_1cf83f3e ON public.archerysettings_nmapvulnerssettingdb USING btree (updated_by_id);


--
-- Name: archerysettings_openvassettingdb_created_by_id_3ceed51b; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_openvassettingdb_created_by_id_3ceed51b ON public.archerysettings_openvassettingdb USING btree (created_by_id);


--
-- Name: archerysettings_openvassettingdb_organization_id_a074799d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_openvassettingdb_organization_id_a074799d ON public.archerysettings_openvassettingdb USING btree (organization_id);


--
-- Name: archerysettings_openvassettingdb_updated_by_id_b23b9a04; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_openvassettingdb_updated_by_id_b23b9a04 ON public.archerysettings_openvassettingdb USING btree (updated_by_id);


--
-- Name: archerysettings_settingsdb_created_by_id_787559c8; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_settingsdb_created_by_id_787559c8 ON public.archerysettings_settingsdb USING btree (created_by_id);


--
-- Name: archerysettings_settingsdb_organization_id_fca7e2f3; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_settingsdb_organization_id_fca7e2f3 ON public.archerysettings_settingsdb USING btree (organization_id);


--
-- Name: archerysettings_settingsdb_updated_by_id_a254c306; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_settingsdb_updated_by_id_a254c306 ON public.archerysettings_settingsdb USING btree (updated_by_id);


--
-- Name: archerysettings_zapsettingsdb_created_by_id_03efd812; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_zapsettingsdb_created_by_id_03efd812 ON public.archerysettings_zapsettingsdb USING btree (created_by_id);


--
-- Name: archerysettings_zapsettingsdb_organization_id_bf54f8e8; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_zapsettingsdb_organization_id_bf54f8e8 ON public.archerysettings_zapsettingsdb USING btree (organization_id);


--
-- Name: archerysettings_zapsettingsdb_updated_by_id_bcc4bd86; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX archerysettings_zapsettingsdb_updated_by_id_bcc4bd86 ON public.archerysettings_zapsettingsdb USING btree (updated_by_id);


--
-- Name: audit_log_action_b32d4d_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX audit_log_action_b32d4d_idx ON public.audit_log USING btree (action);


--
-- Name: audit_log_created_at_24c1f1be; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX audit_log_created_at_24c1f1be ON public.audit_log USING btree (created_at);


--
-- Name: audit_log_resourc_2570dd_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX audit_log_resourc_2570dd_idx ON public.audit_log USING btree (resource_type, resource_id);


--
-- Name: audit_log_user_id_3b54b4_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX audit_log_user_id_3b54b4_idx ON public.audit_log USING btree (user_id, created_at);


--
-- Name: audit_log_user_id_a1b3392d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX audit_log_user_id_a1b3392d ON public.audit_log USING btree (user_id);


--
-- Name: auth_group_name_a6ea08ec_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX auth_group_name_a6ea08ec_like ON public.auth_group USING btree (name varchar_pattern_ops);


--
-- Name: auth_group_permissions_group_id_b120cbf9; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX auth_group_permissions_group_id_b120cbf9 ON public.auth_group_permissions USING btree (group_id);


--
-- Name: auth_group_permissions_permission_id_84c5c92e; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX auth_group_permissions_permission_id_84c5c92e ON public.auth_group_permissions USING btree (permission_id);


--
-- Name: auth_permission_content_type_id_2f476e4b; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX auth_permission_content_type_id_2f476e4b ON public.auth_permission USING btree (content_type_id);


--
-- Name: authtoken_token_key_10f0b77e_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX authtoken_token_key_10f0b77e_like ON public.authtoken_token USING btree (key varchar_pattern_ops);


--
-- Name: cicd_scannercommand_created_by_id_397b9cdf; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cicd_scannercommand_created_by_id_397b9cdf ON public.cicd_scannercommand USING btree (created_by_id);


--
-- Name: cicd_scannercommand_organization_id_0d632366; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cicd_scannercommand_organization_id_0d632366 ON public.cicd_scannercommand USING btree (organization_id);


--
-- Name: cicd_scannercommand_updated_by_id_ee20f46f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cicd_scannercommand_updated_by_id_ee20f46f ON public.cicd_scannercommand USING btree (updated_by_id);


--
-- Name: cicddb_created_by_id_c39d49cc; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cicddb_created_by_id_c39d49cc ON public.cicddb USING btree (created_by_id);


--
-- Name: cicddb_organization_id_2067f304; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cicddb_organization_id_2067f304 ON public.cicddb USING btree (organization_id);


--
-- Name: cicddb_project_id_824fb8ad; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cicddb_project_id_824fb8ad ON public.cicddb USING btree (project_id);


--
-- Name: cicddb_updated_by_id_14551a2d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cicddb_updated_by_id_14551a2d ON public.cicddb USING btree (updated_by_id);


--
-- Name: cloudscansdb_created_by_id_aaff29d2; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cloudscansdb_created_by_id_aaff29d2 ON public.cloudscansdb USING btree (created_by_id);


--
-- Name: cloudscansdb_organization_id_8ebec835; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cloudscansdb_organization_id_8ebec835 ON public.cloudscansdb USING btree (organization_id);


--
-- Name: cloudscansdb_project_id_8aa57327; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cloudscansdb_project_id_8aa57327 ON public.cloudscansdb USING btree (project_id);


--
-- Name: cloudscansdb_updated_by_id_ef2a3150; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cloudscansdb_updated_by_id_ef2a3150 ON public.cloudscansdb USING btree (updated_by_id);


--
-- Name: cloudscansresultsdb_created_by_id_02fdcda1; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cloudscansresultsdb_created_by_id_02fdcda1 ON public.cloudscansresultsdb USING btree (created_by_id);


--
-- Name: cloudscansresultsdb_organization_id_51920662; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cloudscansresultsdb_organization_id_51920662 ON public.cloudscansresultsdb USING btree (organization_id);


--
-- Name: cloudscansresultsdb_project_id_9572f586; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cloudscansresultsdb_project_id_9572f586 ON public.cloudscansresultsdb USING btree (project_id);


--
-- Name: cloudscansresultsdb_updated_by_id_28fd3d4b; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX cloudscansresultsdb_updated_by_id_28fd3d4b ON public.cloudscansresultsdb USING btree (updated_by_id);


--
-- Name: django_admin_log_content_type_id_c4bce8eb; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX django_admin_log_content_type_id_c4bce8eb ON public.django_admin_log USING btree (content_type_id);


--
-- Name: django_admin_log_user_id_c564eba6; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX django_admin_log_user_id_c564eba6 ON public.django_admin_log USING btree (user_id);


--
-- Name: django_session_expire_date_a5c62663; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX django_session_expire_date_a5c62663 ON public.django_session USING btree (expire_date);


--
-- Name: django_session_session_key_c0390e0f_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX django_session_session_key_c0390e0f_like ON public.django_session USING btree (session_key varchar_pattern_ops);


--
-- Name: docklescandb_created_by_id_d6542a17; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX docklescandb_created_by_id_d6542a17 ON public.docklescandb USING btree (created_by_id);


--
-- Name: docklescandb_organization_id_ef74a3a8; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX docklescandb_organization_id_ef74a3a8 ON public.docklescandb USING btree (organization_id);


--
-- Name: docklescandb_project_id_defa4106; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX docklescandb_project_id_defa4106 ON public.docklescandb USING btree (project_id);


--
-- Name: docklescandb_updated_by_id_7957ac87; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX docklescandb_updated_by_id_7957ac87 ON public.docklescandb USING btree (updated_by_id);


--
-- Name: docklescanresultsdb_created_by_id_4ced903a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX docklescanresultsdb_created_by_id_4ced903a ON public.docklescanresultsdb USING btree (created_by_id);


--
-- Name: docklescanresultsdb_organization_id_8e0e203b; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX docklescanresultsdb_organization_id_8e0e203b ON public.docklescanresultsdb USING btree (organization_id);


--
-- Name: docklescanresultsdb_project_id_bd864eca; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX docklescanresultsdb_project_id_bd864eca ON public.docklescanresultsdb USING btree (project_id);


--
-- Name: docklescanresultsdb_updated_by_id_ef9f10e1; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX docklescanresultsdb_updated_by_id_ef9f10e1 ON public.docklescanresultsdb USING btree (updated_by_id);


--
-- Name: inspecscandb_created_by_id_f8654a38; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX inspecscandb_created_by_id_f8654a38 ON public.inspecscandb USING btree (created_by_id);


--
-- Name: inspecscandb_organization_id_7ff48417; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX inspecscandb_organization_id_7ff48417 ON public.inspecscandb USING btree (organization_id);


--
-- Name: inspecscandb_project_id_d31873ae; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX inspecscandb_project_id_d31873ae ON public.inspecscandb USING btree (project_id);


--
-- Name: inspecscandb_updated_by_id_c8b019e4; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX inspecscandb_updated_by_id_c8b019e4 ON public.inspecscandb USING btree (updated_by_id);


--
-- Name: inspecscanresultdb_created_by_id_8a6a4d98; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX inspecscanresultdb_created_by_id_8a6a4d98 ON public.inspecscanresultdb USING btree (created_by_id);


--
-- Name: inspecscanresultdb_organization_id_cd287171; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX inspecscanresultdb_organization_id_cd287171 ON public.inspecscanresultdb USING btree (organization_id);


--
-- Name: inspecscanresultdb_project_id_3020d33c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX inspecscanresultdb_project_id_3020d33c ON public.inspecscanresultdb USING btree (project_id);


--
-- Name: inspecscanresultdb_updated_by_id_4619f3d5; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX inspecscanresultdb_updated_by_id_4619f3d5 ON public.inspecscanresultdb USING btree (updated_by_id);


--
-- Name: jiraticketing_jirasetting_created_by_id_cae43d6b; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX jiraticketing_jirasetting_created_by_id_cae43d6b ON public.jiraticketing_jirasetting USING btree (created_by_id);


--
-- Name: jiraticketing_jirasetting_organization_id_febab4d9; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX jiraticketing_jirasetting_organization_id_febab4d9 ON public.jiraticketing_jirasetting USING btree (organization_id);


--
-- Name: jiraticketing_jirasetting_updated_by_id_4d7f76f4; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX jiraticketing_jirasetting_updated_by_id_4d7f76f4 ON public.jiraticketing_jirasetting USING btree (updated_by_id);


--
-- Name: monthdb_created_by_id_4521f1e9; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX monthdb_created_by_id_4521f1e9 ON public.monthdb USING btree (created_by_id);


--
-- Name: monthdb_organization_id_bb6e8727; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX monthdb_organization_id_bb6e8727 ON public.monthdb USING btree (organization_id);


--
-- Name: monthdb_project_id_ed5ff304; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX monthdb_project_id_ed5ff304 ON public.monthdb USING btree (project_id);


--
-- Name: monthdb_updated_by_id_40ac3547; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX monthdb_updated_by_id_40ac3547 ON public.monthdb USING btree (updated_by_id);


--
-- Name: networkscandb_created_by_id_3521afaf; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX networkscandb_created_by_id_3521afaf ON public.networkscandb USING btree (created_by_id);


--
-- Name: networkscandb_organization_id_53d68902; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX networkscandb_organization_id_53d68902 ON public.networkscandb USING btree (organization_id);


--
-- Name: networkscandb_project_id_1a601b0c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX networkscandb_project_id_1a601b0c ON public.networkscandb USING btree (project_id);


--
-- Name: networkscandb_updated_by_id_4855695c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX networkscandb_updated_by_id_4855695c ON public.networkscandb USING btree (updated_by_id);


--
-- Name: networkscanresultsdb_created_by_id_3cc1d12c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX networkscanresultsdb_created_by_id_3cc1d12c ON public.networkscanresultsdb USING btree (created_by_id);


--
-- Name: networkscanresultsdb_organization_id_3d2ce669; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX networkscanresultsdb_organization_id_3d2ce669 ON public.networkscanresultsdb USING btree (organization_id);


--
-- Name: networkscanresultsdb_project_id_e16a6254; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX networkscanresultsdb_project_id_e16a6254 ON public.networkscanresultsdb USING btree (project_id);


--
-- Name: networkscanresultsdb_updated_by_id_90015591; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX networkscanresultsdb_updated_by_id_90015591 ON public.networkscanresultsdb USING btree (updated_by_id);


--
-- Name: notifications_notification_action_object_content_type_7d2b8ee9; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_action_object_content_type_7d2b8ee9 ON public.notifications_notification USING btree (action_object_content_type_id);


--
-- Name: notifications_notification_actor_content_type_id_0c69d7b7; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_actor_content_type_id_0c69d7b7 ON public.notifications_notification USING btree (actor_content_type_id);


--
-- Name: notifications_notification_deleted_b32b69e6; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_deleted_b32b69e6 ON public.notifications_notification USING btree (deleted);


--
-- Name: notifications_notification_emailed_23a5ad81; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_emailed_23a5ad81 ON public.notifications_notification USING btree (emailed);


--
-- Name: notifications_notification_public_1bc30b1c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_public_1bc30b1c ON public.notifications_notification USING btree (public);


--
-- Name: notifications_notification_recipient_id_d055f3f0; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_recipient_id_d055f3f0 ON public.notifications_notification USING btree (recipient_id);


--
-- Name: notifications_notification_recipient_id_unread_253aadc9_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_recipient_id_unread_253aadc9_idx ON public.notifications_notification USING btree (recipient_id, unread);


--
-- Name: notifications_notification_target_content_type_id_ccb24d88; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_target_content_type_id_ccb24d88 ON public.notifications_notification USING btree (target_content_type_id);


--
-- Name: notifications_notification_timestamp_6a797bad; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_timestamp_6a797bad ON public.notifications_notification USING btree ("timestamp");


--
-- Name: notifications_notification_unread_cce4be30; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX notifications_notification_unread_cce4be30 ON public.notifications_notification USING btree (unread);


--
-- Name: nvd_cache_cve_id_d790149d_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX nvd_cache_cve_id_d790149d_like ON public.nvd_cache USING btree (cve_id varchar_pattern_ops);


--
-- Name: org_apikey_created_by_id_0ea25405; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX org_apikey_created_by_id_0ea25405 ON public.org_apikey USING btree (created_by_id);


--
-- Name: org_apikey_organization_id_375610c5; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX org_apikey_organization_id_375610c5 ON public.org_apikey USING btree (organization_id);


--
-- Name: pentest_pentestscandb_created_by_id_f6688fa7; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_pentestscandb_created_by_id_f6688fa7 ON public.pentest_pentestscandb USING btree (created_by_id);


--
-- Name: pentest_pentestscandb_organization_id_eaf70e53; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_pentestscandb_organization_id_eaf70e53 ON public.pentest_pentestscandb USING btree (organization_id);


--
-- Name: pentest_pentestscandb_project_id_2c6d5ef1; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_pentestscandb_project_id_2c6d5ef1 ON public.pentest_pentestscandb USING btree (project_id);


--
-- Name: pentest_pentestscandb_updated_by_id_c3396981; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_pentestscandb_updated_by_id_c3396981 ON public.pentest_pentestscandb USING btree (updated_by_id);


--
-- Name: pentest_pentestscanresultsdb_created_by_id_ed90b6f0; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_pentestscanresultsdb_created_by_id_ed90b6f0 ON public.pentest_pentestscanresultsdb USING btree (created_by_id);


--
-- Name: pentest_pentestscanresultsdb_organization_id_7dd52823; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_pentestscanresultsdb_organization_id_7dd52823 ON public.pentest_pentestscanresultsdb USING btree (organization_id);


--
-- Name: pentest_pentestscanresultsdb_project_id_3e1a138c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_pentestscanresultsdb_project_id_3e1a138c ON public.pentest_pentestscanresultsdb USING btree (project_id);


--
-- Name: pentest_pentestscanresultsdb_updated_by_id_d100813f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_pentestscanresultsdb_updated_by_id_d100813f ON public.pentest_pentestscanresultsdb USING btree (updated_by_id);


--
-- Name: pentest_vulnerabilitydata_created_by_id_c635093a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_vulnerabilitydata_created_by_id_c635093a ON public.pentest_vulnerabilitydata USING btree (created_by_id);


--
-- Name: pentest_vulnerabilitydata_organization_id_49da490c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_vulnerabilitydata_organization_id_49da490c ON public.pentest_vulnerabilitydata USING btree (organization_id);


--
-- Name: pentest_vulnerabilitydata_updated_by_id_f4638d99; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX pentest_vulnerabilitydata_updated_by_id_f4638d99 ON public.pentest_vulnerabilitydata USING btree (updated_by_id);


--
-- Name: project_created_by_id_6cc13408; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX project_created_by_id_6cc13408 ON public.project USING btree (created_by_id);


--
-- Name: project_organization_id_3c9f74fb; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX project_organization_id_3c9f74fb ON public.project USING btree (organization_id);


--
-- Name: project_updated_by_id_fe290525; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX project_updated_by_id_fe290525 ON public.project USING btree (updated_by_id);


--
-- Name: projectscandb_created_by_id_c8a6cc30; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX projectscandb_created_by_id_c8a6cc30 ON public.projectscandb USING btree (created_by_id);


--
-- Name: projectscandb_organization_id_6e65fb28; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX projectscandb_organization_id_6e65fb28 ON public.projectscandb USING btree (organization_id);


--
-- Name: projectscandb_project_id_61163a1a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX projectscandb_project_id_61163a1a ON public.projectscandb USING btree (project_id);


--
-- Name: projectscandb_updated_by_id_d959d6ce; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX projectscandb_updated_by_id_d959d6ce ON public.projectscandb USING btree (updated_by_id);


--
-- Name: sitetree_tree_alias_c897c375_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_tree_alias_c897c375_like ON public.sitetree_tree USING btree (alias varchar_pattern_ops);


--
-- Name: sitetree_treeitem_access_guest_09916132; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_access_guest_09916132 ON public.sitetree_treeitem USING btree (access_guest);


--
-- Name: sitetree_treeitem_access_loggedin_8a523197; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_access_loggedin_8a523197 ON public.sitetree_treeitem USING btree (access_loggedin);


--
-- Name: sitetree_treeitem_access_permissions_permission_id_c6d1d87a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_access_permissions_permission_id_c6d1d87a ON public.sitetree_treeitem_access_permissions USING btree (permission_id);


--
-- Name: sitetree_treeitem_access_permissions_treeitem_id_aedb7367; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_access_permissions_treeitem_id_aedb7367 ON public.sitetree_treeitem_access_permissions USING btree (treeitem_id);


--
-- Name: sitetree_treeitem_access_restricted_e9c87676; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_access_restricted_e9c87676 ON public.sitetree_treeitem USING btree (access_restricted);


--
-- Name: sitetree_treeitem_alias_33dc5690; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_alias_33dc5690 ON public.sitetree_treeitem USING btree (alias);


--
-- Name: sitetree_treeitem_alias_33dc5690_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_alias_33dc5690_like ON public.sitetree_treeitem USING btree (alias varchar_pattern_ops);


--
-- Name: sitetree_treeitem_hidden_5de28c6e; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_hidden_5de28c6e ON public.sitetree_treeitem USING btree (hidden);


--
-- Name: sitetree_treeitem_inbreadcrumbs_ebb24448; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_inbreadcrumbs_ebb24448 ON public.sitetree_treeitem USING btree (inbreadcrumbs);


--
-- Name: sitetree_treeitem_inmenu_ccabc0b0; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_inmenu_ccabc0b0 ON public.sitetree_treeitem USING btree (inmenu);


--
-- Name: sitetree_treeitem_insitetree_60c593a5; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_insitetree_60c593a5 ON public.sitetree_treeitem USING btree (insitetree);


--
-- Name: sitetree_treeitem_parent_id_88f6f9a4; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_parent_id_88f6f9a4 ON public.sitetree_treeitem USING btree (parent_id);


--
-- Name: sitetree_treeitem_sort_order_93fd716c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_sort_order_93fd716c ON public.sitetree_treeitem USING btree (sort_order);


--
-- Name: sitetree_treeitem_tree_id_038a4bc7; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_tree_id_038a4bc7 ON public.sitetree_treeitem USING btree (tree_id);


--
-- Name: sitetree_treeitem_url_b91ef35a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_url_b91ef35a ON public.sitetree_treeitem USING btree (url);


--
-- Name: sitetree_treeitem_url_b91ef35a_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_url_b91ef35a_like ON public.sitetree_treeitem USING btree (url varchar_pattern_ops);


--
-- Name: sitetree_treeitem_urlaspattern_ff432a51; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX sitetree_treeitem_urlaspattern_ff432a51 ON public.sitetree_treeitem USING btree (urlaspattern);


--
-- Name: staticscanresultsdb_created_by_id_a4150f56; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX staticscanresultsdb_created_by_id_a4150f56 ON public.staticscanresultsdb USING btree (created_by_id);


--
-- Name: staticscanresultsdb_organization_id_be63a55f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX staticscanresultsdb_organization_id_be63a55f ON public.staticscanresultsdb USING btree (organization_id);


--
-- Name: staticscanresultsdb_project_id_3e094359; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX staticscanresultsdb_project_id_3e094359 ON public.staticscanresultsdb USING btree (project_id);


--
-- Name: staticscanresultsdb_updated_by_id_97acf55d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX staticscanresultsdb_updated_by_id_97acf55d ON public.staticscanresultsdb USING btree (updated_by_id);


--
-- Name: staticscansdb_created_by_id_7186505b; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX staticscansdb_created_by_id_7186505b ON public.staticscansdb USING btree (created_by_id);


--
-- Name: staticscansdb_organization_id_c36cf550; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX staticscansdb_organization_id_c36cf550 ON public.staticscansdb USING btree (organization_id);


--
-- Name: staticscansdb_project_id_1de74de4; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX staticscansdb_project_id_1de74de4 ON public.staticscansdb USING btree (project_id);


--
-- Name: staticscansdb_updated_by_id_a983d90d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX staticscansdb_updated_by_id_a983d90d ON public.staticscansdb USING btree (updated_by_id);


--
-- Name: taskscheduledb_created_by_id_e52428fa; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX taskscheduledb_created_by_id_e52428fa ON public.taskscheduledb USING btree (created_by_id);


--
-- Name: taskscheduledb_organization_id_c5c20b4c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX taskscheduledb_organization_id_c5c20b4c ON public.taskscheduledb USING btree (organization_id);


--
-- Name: taskscheduledb_updated_by_id_54509ac7; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX taskscheduledb_updated_by_id_54509ac7 ON public.taskscheduledb USING btree (updated_by_id);


--
-- Name: token_blacklist_outstandingtoken_jti_hex_d9bdf6f7_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX token_blacklist_outstandingtoken_jti_hex_d9bdf6f7_like ON public.token_blacklist_outstandingtoken USING btree (jti varchar_pattern_ops);


--
-- Name: token_blacklist_outstandingtoken_user_id_83bc629a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX token_blacklist_outstandingtoken_user_id_83bc629a ON public.token_blacklist_outstandingtoken USING btree (user_id);


--
-- Name: tools_niktoresultdb_created_by_id_f67ad40a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_niktoresultdb_created_by_id_f67ad40a ON public.tools_niktoresultdb USING btree (created_by_id);


--
-- Name: tools_niktoresultdb_organization_id_11163cad; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_niktoresultdb_organization_id_11163cad ON public.tools_niktoresultdb USING btree (organization_id);


--
-- Name: tools_niktoresultdb_project_id_9755b23b; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_niktoresultdb_project_id_9755b23b ON public.tools_niktoresultdb USING btree (project_id);


--
-- Name: tools_niktoresultdb_updated_by_id_cbbe7768; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_niktoresultdb_updated_by_id_cbbe7768 ON public.tools_niktoresultdb USING btree (updated_by_id);


--
-- Name: tools_niktovulndb_created_by_id_95854d18; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_niktovulndb_created_by_id_95854d18 ON public.tools_niktovulndb USING btree (created_by_id);


--
-- Name: tools_niktovulndb_organization_id_6215248c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_niktovulndb_organization_id_6215248c ON public.tools_niktovulndb USING btree (organization_id);


--
-- Name: tools_niktovulndb_project_id_e123408c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_niktovulndb_project_id_e123408c ON public.tools_niktovulndb USING btree (project_id);


--
-- Name: tools_niktovulndb_updated_by_id_d6f07a25; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_niktovulndb_updated_by_id_d6f07a25 ON public.tools_niktovulndb USING btree (updated_by_id);


--
-- Name: tools_nmapresultdb_created_by_id_8e891749; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_nmapresultdb_created_by_id_8e891749 ON public.tools_nmapresultdb USING btree (created_by_id);


--
-- Name: tools_nmapresultdb_organization_id_5f8f289d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_nmapresultdb_organization_id_5f8f289d ON public.tools_nmapresultdb USING btree (organization_id);


--
-- Name: tools_nmapresultdb_project_id_66621e3f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_nmapresultdb_project_id_66621e3f ON public.tools_nmapresultdb USING btree (project_id);


--
-- Name: tools_nmapresultdb_updated_by_id_4217a31a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_nmapresultdb_updated_by_id_4217a31a ON public.tools_nmapresultdb USING btree (updated_by_id);


--
-- Name: tools_nmapscandb_created_by_id_13003939; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_nmapscandb_created_by_id_13003939 ON public.tools_nmapscandb USING btree (created_by_id);


--
-- Name: tools_nmapscandb_organization_id_8ff7ecb5; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_nmapscandb_organization_id_8ff7ecb5 ON public.tools_nmapscandb USING btree (organization_id);


--
-- Name: tools_nmapscandb_project_id_04432555; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_nmapscandb_project_id_04432555 ON public.tools_nmapscandb USING btree (project_id);


--
-- Name: tools_nmapscandb_updated_by_id_c1523606; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_nmapscandb_updated_by_id_c1523606 ON public.tools_nmapscandb USING btree (updated_by_id);


--
-- Name: tools_sslscanresultdb_created_by_id_b4885d73; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_sslscanresultdb_created_by_id_b4885d73 ON public.tools_sslscanresultdb USING btree (created_by_id);


--
-- Name: tools_sslscanresultdb_organization_id_d5960e4a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_sslscanresultdb_organization_id_d5960e4a ON public.tools_sslscanresultdb USING btree (organization_id);


--
-- Name: tools_sslscanresultdb_project_id_4126175f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_sslscanresultdb_project_id_4126175f ON public.tools_sslscanresultdb USING btree (project_id);


--
-- Name: tools_sslscanresultdb_updated_by_id_ae4abd7d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX tools_sslscanresultdb_updated_by_id_ae4abd7d ON public.tools_sslscanresultdb USING btree (updated_by_id);


--
-- Name: unified_sca_created_768ee0_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_created_768ee0_idx ON public.unified_scan_result USING btree (created_at);


--
-- Name: unified_sca_dup_has_20b455_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_dup_has_20b455_idx ON public.unified_scan_result USING btree (dup_hash, organization_id);


--
-- Name: unified_sca_scan_id_0c36e3_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_scan_id_0c36e3_idx ON public.unified_scan_result USING btree (scan_id, scan_type);


--
-- Name: unified_sca_scan_st_d1f776_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_scan_st_d1f776_idx ON public.unified_scan_summary USING btree (scan_status, organization_id);


--
-- Name: unified_sca_scan_ty_0affd8_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_scan_ty_0affd8_idx ON public.unified_scan_summary USING btree (scan_type, organization_id);


--
-- Name: unified_sca_scan_ty_687ca0_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_scan_ty_687ca0_idx ON public.unified_scan_config USING btree (scan_type, organization_id);


--
-- Name: unified_sca_scan_ty_a4c5cc_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_scan_ty_a4c5cc_idx ON public.unified_scan_result USING btree (scan_type, organization_id);


--
-- Name: unified_sca_scanner_d0e0c7_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_scanner_d0e0c7_idx ON public.unified_scan_result USING btree (scanner_name, organization_id);


--
-- Name: unified_sca_scanner_ed0dcd_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_scanner_ed0dcd_idx ON public.unified_scan_config USING btree (scanner_name, organization_id);


--
-- Name: unified_sca_severit_8b3a2c_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_severit_8b3a2c_idx ON public.unified_scan_result USING btree (severity, organization_id);


--
-- Name: unified_sca_vuln_st_0e1c4e_idx; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_sca_vuln_st_0e1c4e_idx ON public.unified_scan_result USING btree (vuln_status, organization_id);


--
-- Name: unified_scan_config_created_by_id_8566203f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_config_created_by_id_8566203f ON public.unified_scan_config USING btree (created_by_id);


--
-- Name: unified_scan_config_organization_id_9f06312c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_config_organization_id_9f06312c ON public.unified_scan_config USING btree (organization_id);


--
-- Name: unified_scan_config_project_id_c108b478; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_config_project_id_c108b478 ON public.unified_scan_config USING btree (project_id);


--
-- Name: unified_scan_result_created_by_id_a47e1412; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_result_created_by_id_a47e1412 ON public.unified_scan_result USING btree (created_by_id);


--
-- Name: unified_scan_result_dup_hash_4d8dd55f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_result_dup_hash_4d8dd55f ON public.unified_scan_result USING btree (dup_hash);


--
-- Name: unified_scan_result_dup_hash_4d8dd55f_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_result_dup_hash_4d8dd55f_like ON public.unified_scan_result USING btree (dup_hash varchar_pattern_ops);


--
-- Name: unified_scan_result_organization_id_1763d7fa; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_result_organization_id_1763d7fa ON public.unified_scan_result USING btree (organization_id);


--
-- Name: unified_scan_result_project_id_ff279361; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_result_project_id_ff279361 ON public.unified_scan_result USING btree (project_id);


--
-- Name: unified_scan_summary_created_by_id_8de27a8f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_summary_created_by_id_8de27a8f ON public.unified_scan_summary USING btree (created_by_id);


--
-- Name: unified_scan_summary_organization_id_33040816; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_summary_organization_id_33040816 ON public.unified_scan_summary USING btree (organization_id);


--
-- Name: unified_scan_summary_project_id_4de4fc41; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX unified_scan_summary_project_id_4de4fc41 ON public.unified_scan_summary USING btree (project_id);


--
-- Name: user_login_history_user_id_44060508; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX user_login_history_user_id_44060508 ON public.user_login_history USING btree (user_id);


--
-- Name: user_profile_email_16c4b6e6_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX user_profile_email_16c4b6e6_like ON public.user_profile USING btree (email varchar_pattern_ops);


--
-- Name: user_profile_groups_group_id_864f8fbf; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX user_profile_groups_group_id_864f8fbf ON public.user_profile_groups USING btree (group_id);


--
-- Name: user_profile_groups_userprofile_id_3e52d209; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX user_profile_groups_userprofile_id_3e52d209 ON public.user_profile_groups USING btree (userprofile_id);


--
-- Name: user_profile_organization_id_836b384f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX user_profile_organization_id_836b384f ON public.user_profile USING btree (organization_id);


--
-- Name: user_profile_role_id_7f4a52a2; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX user_profile_role_id_7f4a52a2 ON public.user_profile USING btree (role_id);


--
-- Name: user_profile_user_permissions_permission_id_f5abe73f; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX user_profile_user_permissions_permission_id_f5abe73f ON public.user_profile_user_permissions USING btree (permission_id);


--
-- Name: user_profile_user_permissions_userprofile_id_663dc0ea; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX user_profile_user_permissions_userprofile_id_663dc0ea ON public.user_profile_user_permissions USING btree (userprofile_id);


--
-- Name: user_roles_role_7897db55_like; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX user_roles_role_7897db55_like ON public.user_roles USING btree (role varchar_pattern_ops);


--
-- Name: webscanResultsdb_created_by_id_83b8eb6c; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX "webscanResultsdb_created_by_id_83b8eb6c" ON public."webscanResultsdb" USING btree (created_by_id);


--
-- Name: webscanResultsdb_organization_id_f4197910; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX "webscanResultsdb_organization_id_f4197910" ON public."webscanResultsdb" USING btree (organization_id);


--
-- Name: webscanResultsdb_project_id_c311d308; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX "webscanResultsdb_project_id_c311d308" ON public."webscanResultsdb" USING btree (project_id);


--
-- Name: webscanResultsdb_updated_by_id_bcaa5fd0; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX "webscanResultsdb_updated_by_id_bcaa5fd0" ON public."webscanResultsdb" USING btree (updated_by_id);


--
-- Name: webscandb_created_by_id_48de06d3; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscandb_created_by_id_48de06d3 ON public.webscandb USING btree (created_by_id);


--
-- Name: webscandb_organization_id_be728f52; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscandb_organization_id_be728f52 ON public.webscandb USING btree (organization_id);


--
-- Name: webscandb_project_id_19355904; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscandb_project_id_19355904 ON public.webscandb USING btree (project_id);


--
-- Name: webscandb_updated_by_id_973472a0; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscandb_updated_by_id_973472a0 ON public.webscandb USING btree (updated_by_id);


--
-- Name: webscanners_burp_issue_definitions_created_by_id_6cdbccff; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_burp_issue_definitions_created_by_id_6cdbccff ON public.webscanners_burp_issue_definitions USING btree (created_by_id);


--
-- Name: webscanners_burp_issue_definitions_organization_id_49ebd2fb; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_burp_issue_definitions_organization_id_49ebd2fb ON public.webscanners_burp_issue_definitions USING btree (organization_id);


--
-- Name: webscanners_burp_issue_definitions_updated_by_id_1c5ec145; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_burp_issue_definitions_updated_by_id_1c5ec145 ON public.webscanners_burp_issue_definitions USING btree (updated_by_id);


--
-- Name: webscanners_email_config_db_created_by_id_8d8dfad7; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_email_config_db_created_by_id_8d8dfad7 ON public.webscanners_email_config_db USING btree (created_by_id);


--
-- Name: webscanners_email_config_db_organization_id_4e059e49; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_email_config_db_organization_id_4e059e49 ON public.webscanners_email_config_db USING btree (organization_id);


--
-- Name: webscanners_email_config_db_updated_by_id_727f109d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_email_config_db_updated_by_id_727f109d ON public.webscanners_email_config_db USING btree (updated_by_id);


--
-- Name: webscanners_task_schedule_db_created_by_id_9f9f5c3a; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_task_schedule_db_created_by_id_9f9f5c3a ON public.webscanners_task_schedule_db USING btree (created_by_id);


--
-- Name: webscanners_task_schedule_db_organization_id_1d3ffe8e; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_task_schedule_db_organization_id_1d3ffe8e ON public.webscanners_task_schedule_db USING btree (organization_id);


--
-- Name: webscanners_task_schedule_db_project_id_29b5865d; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_task_schedule_db_project_id_29b5865d ON public.webscanners_task_schedule_db USING btree (project_id);


--
-- Name: webscanners_task_schedule_db_updated_by_id_854c5760; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_task_schedule_db_updated_by_id_854c5760 ON public.webscanners_task_schedule_db USING btree (updated_by_id);


--
-- Name: webscanners_web_scan_db_created_by_id_24641621; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_web_scan_db_created_by_id_24641621 ON public.webscanners_web_scan_db USING btree (created_by_id);


--
-- Name: webscanners_web_scan_db_organization_id_32499307; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_web_scan_db_organization_id_32499307 ON public.webscanners_web_scan_db USING btree (organization_id);


--
-- Name: webscanners_web_scan_db_project_id_bcee2505; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_web_scan_db_project_id_bcee2505 ON public.webscanners_web_scan_db USING btree (project_id);


--
-- Name: webscanners_web_scan_db_updated_by_id_9b793373; Type: INDEX; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

CREATE INDEX webscanners_web_scan_db_updated_by_id_9b793373 ON public.webscanners_web_scan_db USING btree (updated_by_id);


--
-- Name: archerysettings_arachnisettingsdb archerysettings_arac_created_by_id_a8df6663_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_arachnisettingsdb
    ADD CONSTRAINT archerysettings_arac_created_by_id_a8df6663_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_arachnisettingsdb archerysettings_arac_organization_id_0f8a5748_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_arachnisettingsdb
    ADD CONSTRAINT archerysettings_arac_organization_id_0f8a5748_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_arachnisettingsdb archerysettings_arac_updated_by_id_43478b8a_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_arachnisettingsdb
    ADD CONSTRAINT archerysettings_arac_updated_by_id_43478b8a_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_burpsettingdb archerysettings_burp_created_by_id_3a9630f1_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_burpsettingdb
    ADD CONSTRAINT archerysettings_burp_created_by_id_3a9630f1_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_burpsettingdb archerysettings_burp_organization_id_a2c1c614_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_burpsettingdb
    ADD CONSTRAINT archerysettings_burp_organization_id_a2c1c614_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_burpsettingdb archerysettings_burp_updated_by_id_115f4907_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_burpsettingdb
    ADD CONSTRAINT archerysettings_burp_updated_by_id_115f4907_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_emaildb archerysettings_emai_created_by_id_5b4b004d_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_emaildb
    ADD CONSTRAINT archerysettings_emai_created_by_id_5b4b004d_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_emaildb archerysettings_emai_organization_id_801012dc_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_emaildb
    ADD CONSTRAINT archerysettings_emai_organization_id_801012dc_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_emaildb archerysettings_emai_updated_by_id_87e13d8d_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_emaildb
    ADD CONSTRAINT archerysettings_emai_updated_by_id_87e13d8d_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_niktosettingdb archerysettings_nikt_created_by_id_fd0214e2_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_niktosettingdb
    ADD CONSTRAINT archerysettings_nikt_created_by_id_fd0214e2_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_niktosettingdb archerysettings_nikt_organization_id_c1bbbecd_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_niktosettingdb
    ADD CONSTRAINT archerysettings_nikt_organization_id_c1bbbecd_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_niktosettingdb archerysettings_nikt_updated_by_id_f8c81e81_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_niktosettingdb
    ADD CONSTRAINT archerysettings_nikt_updated_by_id_f8c81e81_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_nmapsettingdb archerysettings_nmap_created_by_id_7a7dc24f_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapsettingdb
    ADD CONSTRAINT archerysettings_nmap_created_by_id_7a7dc24f_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_nmapvulnerssettingdb archerysettings_nmap_created_by_id_ad9313ae_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapvulnerssettingdb
    ADD CONSTRAINT archerysettings_nmap_created_by_id_ad9313ae_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_nmapsettingdb archerysettings_nmap_organization_id_41937d18_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapsettingdb
    ADD CONSTRAINT archerysettings_nmap_organization_id_41937d18_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_nmapvulnerssettingdb archerysettings_nmap_organization_id_d54b54e1_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapvulnerssettingdb
    ADD CONSTRAINT archerysettings_nmap_organization_id_d54b54e1_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_nmapvulnerssettingdb archerysettings_nmap_updated_by_id_1cf83f3e_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapvulnerssettingdb
    ADD CONSTRAINT archerysettings_nmap_updated_by_id_1cf83f3e_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_nmapsettingdb archerysettings_nmap_updated_by_id_d727d8d8_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_nmapsettingdb
    ADD CONSTRAINT archerysettings_nmap_updated_by_id_d727d8d8_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_openvassettingdb archerysettings_open_created_by_id_3ceed51b_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_openvassettingdb
    ADD CONSTRAINT archerysettings_open_created_by_id_3ceed51b_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_openvassettingdb archerysettings_open_organization_id_a074799d_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_openvassettingdb
    ADD CONSTRAINT archerysettings_open_organization_id_a074799d_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_openvassettingdb archerysettings_open_updated_by_id_b23b9a04_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_openvassettingdb
    ADD CONSTRAINT archerysettings_open_updated_by_id_b23b9a04_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_settingsdb archerysettings_sett_created_by_id_787559c8_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_settingsdb
    ADD CONSTRAINT archerysettings_sett_created_by_id_787559c8_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_settingsdb archerysettings_sett_organization_id_fca7e2f3_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_settingsdb
    ADD CONSTRAINT archerysettings_sett_organization_id_fca7e2f3_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_settingsdb archerysettings_sett_updated_by_id_a254c306_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_settingsdb
    ADD CONSTRAINT archerysettings_sett_updated_by_id_a254c306_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_zapsettingsdb archerysettings_zaps_created_by_id_03efd812_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_zapsettingsdb
    ADD CONSTRAINT archerysettings_zaps_created_by_id_03efd812_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_zapsettingsdb archerysettings_zaps_organization_id_bf54f8e8_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_zapsettingsdb
    ADD CONSTRAINT archerysettings_zaps_organization_id_bf54f8e8_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: archerysettings_zapsettingsdb archerysettings_zaps_updated_by_id_bcc4bd86_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.archerysettings_zapsettingsdb
    ADD CONSTRAINT archerysettings_zaps_updated_by_id_bcc4bd86_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: audit_log audit_log_user_id_a1b3392d_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_user_id_a1b3392d_fk_user_profile_id FOREIGN KEY (user_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_group_permissions auth_group_permissio_permission_id_84c5c92e_fk_auth_perm; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissio_permission_id_84c5c92e_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_group_permissions auth_group_permissions_group_id_b120cbf9_fk_auth_group_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_group_id_b120cbf9_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_permission auth_permission_content_type_id_2f476e4b_fk_django_co; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_content_type_id_2f476e4b_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: authtoken_token authtoken_token_user_id_35299eff_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.authtoken_token
    ADD CONSTRAINT authtoken_token_user_id_35299eff_fk_user_profile_id FOREIGN KEY (user_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cicd_scannercommand cicd_scannercommand_created_by_id_397b9cdf_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicd_scannercommand
    ADD CONSTRAINT cicd_scannercommand_created_by_id_397b9cdf_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cicd_scannercommand cicd_scannercommand_organization_id_0d632366_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicd_scannercommand
    ADD CONSTRAINT cicd_scannercommand_organization_id_0d632366_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cicd_scannercommand cicd_scannercommand_updated_by_id_ee20f46f_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicd_scannercommand
    ADD CONSTRAINT cicd_scannercommand_updated_by_id_ee20f46f_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cicddb cicddb_created_by_id_c39d49cc_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicddb
    ADD CONSTRAINT cicddb_created_by_id_c39d49cc_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cicddb cicddb_organization_id_2067f304_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicddb
    ADD CONSTRAINT cicddb_organization_id_2067f304_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cicddb cicddb_project_id_824fb8ad_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicddb
    ADD CONSTRAINT cicddb_project_id_824fb8ad_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cicddb cicddb_updated_by_id_14551a2d_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cicddb
    ADD CONSTRAINT cicddb_updated_by_id_14551a2d_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cloudscansdb cloudscansdb_created_by_id_aaff29d2_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansdb
    ADD CONSTRAINT cloudscansdb_created_by_id_aaff29d2_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cloudscansdb cloudscansdb_organization_id_8ebec835_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansdb
    ADD CONSTRAINT cloudscansdb_organization_id_8ebec835_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cloudscansdb cloudscansdb_project_id_8aa57327_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansdb
    ADD CONSTRAINT cloudscansdb_project_id_8aa57327_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cloudscansdb cloudscansdb_updated_by_id_ef2a3150_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansdb
    ADD CONSTRAINT cloudscansdb_updated_by_id_ef2a3150_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cloudscansresultsdb cloudscansresultsdb_created_by_id_02fdcda1_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansresultsdb
    ADD CONSTRAINT cloudscansresultsdb_created_by_id_02fdcda1_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cloudscansresultsdb cloudscansresultsdb_organization_id_51920662_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansresultsdb
    ADD CONSTRAINT cloudscansresultsdb_organization_id_51920662_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cloudscansresultsdb cloudscansresultsdb_project_id_9572f586_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansresultsdb
    ADD CONSTRAINT cloudscansresultsdb_project_id_9572f586_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cloudscansresultsdb cloudscansresultsdb_updated_by_id_28fd3d4b_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.cloudscansresultsdb
    ADD CONSTRAINT cloudscansresultsdb_updated_by_id_28fd3d4b_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: django_admin_log django_admin_log_content_type_id_c4bce8eb_fk_django_co; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_content_type_id_c4bce8eb_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: django_admin_log django_admin_log_user_id_c564eba6_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_user_id_c564eba6_fk_user_profile_id FOREIGN KEY (user_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: docklescandb docklescandb_created_by_id_d6542a17_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescandb
    ADD CONSTRAINT docklescandb_created_by_id_d6542a17_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: docklescandb docklescandb_organization_id_ef74a3a8_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescandb
    ADD CONSTRAINT docklescandb_organization_id_ef74a3a8_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: docklescandb docklescandb_project_id_defa4106_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescandb
    ADD CONSTRAINT docklescandb_project_id_defa4106_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: docklescandb docklescandb_updated_by_id_7957ac87_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescandb
    ADD CONSTRAINT docklescandb_updated_by_id_7957ac87_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: docklescanresultsdb docklescanresultsdb_created_by_id_4ced903a_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescanresultsdb
    ADD CONSTRAINT docklescanresultsdb_created_by_id_4ced903a_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: docklescanresultsdb docklescanresultsdb_organization_id_8e0e203b_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescanresultsdb
    ADD CONSTRAINT docklescanresultsdb_organization_id_8e0e203b_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: docklescanresultsdb docklescanresultsdb_project_id_bd864eca_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescanresultsdb
    ADD CONSTRAINT docklescanresultsdb_project_id_bd864eca_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: docklescanresultsdb docklescanresultsdb_updated_by_id_ef9f10e1_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.docklescanresultsdb
    ADD CONSTRAINT docklescanresultsdb_updated_by_id_ef9f10e1_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: inspecscandb inspecscandb_created_by_id_f8654a38_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscandb
    ADD CONSTRAINT inspecscandb_created_by_id_f8654a38_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: inspecscandb inspecscandb_organization_id_7ff48417_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscandb
    ADD CONSTRAINT inspecscandb_organization_id_7ff48417_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: inspecscandb inspecscandb_project_id_d31873ae_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscandb
    ADD CONSTRAINT inspecscandb_project_id_d31873ae_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: inspecscandb inspecscandb_updated_by_id_c8b019e4_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscandb
    ADD CONSTRAINT inspecscandb_updated_by_id_c8b019e4_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: inspecscanresultdb inspecscanresultdb_created_by_id_8a6a4d98_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscanresultdb
    ADD CONSTRAINT inspecscanresultdb_created_by_id_8a6a4d98_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: inspecscanresultdb inspecscanresultdb_organization_id_cd287171_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscanresultdb
    ADD CONSTRAINT inspecscanresultdb_organization_id_cd287171_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: inspecscanresultdb inspecscanresultdb_project_id_3020d33c_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscanresultdb
    ADD CONSTRAINT inspecscanresultdb_project_id_3020d33c_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: inspecscanresultdb inspecscanresultdb_updated_by_id_4619f3d5_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.inspecscanresultdb
    ADD CONSTRAINT inspecscanresultdb_updated_by_id_4619f3d5_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: jiraticketing_jirasetting jiraticketing_jirase_created_by_id_cae43d6b_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.jiraticketing_jirasetting
    ADD CONSTRAINT jiraticketing_jirase_created_by_id_cae43d6b_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: jiraticketing_jirasetting jiraticketing_jirase_organization_id_febab4d9_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.jiraticketing_jirasetting
    ADD CONSTRAINT jiraticketing_jirase_organization_id_febab4d9_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: jiraticketing_jirasetting jiraticketing_jirase_updated_by_id_4d7f76f4_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.jiraticketing_jirasetting
    ADD CONSTRAINT jiraticketing_jirase_updated_by_id_4d7f76f4_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: monthdb monthdb_created_by_id_4521f1e9_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.monthdb
    ADD CONSTRAINT monthdb_created_by_id_4521f1e9_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: monthdb monthdb_organization_id_bb6e8727_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.monthdb
    ADD CONSTRAINT monthdb_organization_id_bb6e8727_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: monthdb monthdb_project_id_ed5ff304_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.monthdb
    ADD CONSTRAINT monthdb_project_id_ed5ff304_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: monthdb monthdb_updated_by_id_40ac3547_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.monthdb
    ADD CONSTRAINT monthdb_updated_by_id_40ac3547_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: networkscandb networkscandb_created_by_id_3521afaf_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscandb
    ADD CONSTRAINT networkscandb_created_by_id_3521afaf_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: networkscandb networkscandb_organization_id_53d68902_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscandb
    ADD CONSTRAINT networkscandb_organization_id_53d68902_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: networkscandb networkscandb_updated_by_id_4855695c_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscandb
    ADD CONSTRAINT networkscandb_updated_by_id_4855695c_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: networkscanresultsdb networkscanners_netw_project_id_fca32cb3_fk_project_i; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscanresultsdb
    ADD CONSTRAINT networkscanners_netw_project_id_fca32cb3_fk_project_i FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: networkscandb networkscanners_networkscandb_project_id_329a1259_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscandb
    ADD CONSTRAINT networkscanners_networkscandb_project_id_329a1259_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: networkscanresultsdb networkscanresultsdb_created_by_id_3cc1d12c_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscanresultsdb
    ADD CONSTRAINT networkscanresultsdb_created_by_id_3cc1d12c_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: networkscanresultsdb networkscanresultsdb_organization_id_3d2ce669_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscanresultsdb
    ADD CONSTRAINT networkscanresultsdb_organization_id_3d2ce669_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: networkscanresultsdb networkscanresultsdb_updated_by_id_90015591_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.networkscanresultsdb
    ADD CONSTRAINT networkscanresultsdb_updated_by_id_90015591_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: notifications_notification notifications_notifi_action_object_conten_7d2b8ee9_fk_django_co; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.notifications_notification
    ADD CONSTRAINT notifications_notifi_action_object_conten_7d2b8ee9_fk_django_co FOREIGN KEY (action_object_content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: notifications_notification notifications_notifi_actor_content_type_i_0c69d7b7_fk_django_co; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.notifications_notification
    ADD CONSTRAINT notifications_notifi_actor_content_type_i_0c69d7b7_fk_django_co FOREIGN KEY (actor_content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: notifications_notification notifications_notifi_recipient_id_d055f3f0_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.notifications_notification
    ADD CONSTRAINT notifications_notifi_recipient_id_d055f3f0_fk_user_prof FOREIGN KEY (recipient_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: notifications_notification notifications_notifi_target_content_type__ccb24d88_fk_django_co; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.notifications_notification
    ADD CONSTRAINT notifications_notifi_target_content_type__ccb24d88_fk_django_co FOREIGN KEY (target_content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: org_apikey org_apikey_created_by_id_0ea25405_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.org_apikey
    ADD CONSTRAINT org_apikey_created_by_id_0ea25405_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: org_apikey org_apikey_organization_id_375610c5_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.org_apikey
    ADD CONSTRAINT org_apikey_organization_id_375610c5_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_pentestscandb pentest_pentestscand_organization_id_eaf70e53_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscandb
    ADD CONSTRAINT pentest_pentestscand_organization_id_eaf70e53_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_pentestscandb pentest_pentestscandb_created_by_id_f6688fa7_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscandb
    ADD CONSTRAINT pentest_pentestscandb_created_by_id_f6688fa7_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_pentestscandb pentest_pentestscandb_project_id_2c6d5ef1_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscandb
    ADD CONSTRAINT pentest_pentestscandb_project_id_2c6d5ef1_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_pentestscandb pentest_pentestscandb_updated_by_id_c3396981_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscandb
    ADD CONSTRAINT pentest_pentestscandb_updated_by_id_c3396981_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_pentestscanresultsdb pentest_pentestscanr_created_by_id_ed90b6f0_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscanresultsdb
    ADD CONSTRAINT pentest_pentestscanr_created_by_id_ed90b6f0_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_pentestscanresultsdb pentest_pentestscanr_organization_id_7dd52823_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscanresultsdb
    ADD CONSTRAINT pentest_pentestscanr_organization_id_7dd52823_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_pentestscanresultsdb pentest_pentestscanr_updated_by_id_d100813f_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscanresultsdb
    ADD CONSTRAINT pentest_pentestscanr_updated_by_id_d100813f_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_pentestscanresultsdb pentest_pentestscanresultsdb_project_id_3e1a138c_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_pentestscanresultsdb
    ADD CONSTRAINT pentest_pentestscanresultsdb_project_id_3e1a138c_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_vulnerabilitydata pentest_vulnerabilit_created_by_id_c635093a_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_vulnerabilitydata
    ADD CONSTRAINT pentest_vulnerabilit_created_by_id_c635093a_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_vulnerabilitydata pentest_vulnerabilit_organization_id_49da490c_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_vulnerabilitydata
    ADD CONSTRAINT pentest_vulnerabilit_organization_id_49da490c_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: pentest_vulnerabilitydata pentest_vulnerabilit_updated_by_id_f4638d99_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.pentest_vulnerabilitydata
    ADD CONSTRAINT pentest_vulnerabilit_updated_by_id_f4638d99_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project project_created_by_id_6cc13408_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.project
    ADD CONSTRAINT project_created_by_id_6cc13408_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project project_organization_id_3c9f74fb_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.project
    ADD CONSTRAINT project_organization_id_3c9f74fb_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project project_updated_by_id_fe290525_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.project
    ADD CONSTRAINT project_updated_by_id_fe290525_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: projectscandb projectscandb_created_by_id_c8a6cc30_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.projectscandb
    ADD CONSTRAINT projectscandb_created_by_id_c8a6cc30_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: projectscandb projectscandb_organization_id_6e65fb28_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.projectscandb
    ADD CONSTRAINT projectscandb_organization_id_6e65fb28_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: projectscandb projectscandb_project_id_61163a1a_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.projectscandb
    ADD CONSTRAINT projectscandb_project_id_61163a1a_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: projectscandb projectscandb_updated_by_id_d959d6ce_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.projectscandb
    ADD CONSTRAINT projectscandb_updated_by_id_d959d6ce_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: sitetree_treeitem_access_permissions sitetree_treeitem_ac_permission_id_c6d1d87a_fk_auth_perm; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem_access_permissions
    ADD CONSTRAINT sitetree_treeitem_ac_permission_id_c6d1d87a_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: sitetree_treeitem_access_permissions sitetree_treeitem_ac_treeitem_id_aedb7367_fk_sitetree_; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem_access_permissions
    ADD CONSTRAINT sitetree_treeitem_ac_treeitem_id_aedb7367_fk_sitetree_ FOREIGN KEY (treeitem_id) REFERENCES public.sitetree_treeitem(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: sitetree_treeitem sitetree_treeitem_parent_id_88f6f9a4_fk_sitetree_treeitem_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem
    ADD CONSTRAINT sitetree_treeitem_parent_id_88f6f9a4_fk_sitetree_treeitem_id FOREIGN KEY (parent_id) REFERENCES public.sitetree_treeitem(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: sitetree_treeitem sitetree_treeitem_tree_id_038a4bc7_fk_sitetree_tree_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.sitetree_treeitem
    ADD CONSTRAINT sitetree_treeitem_tree_id_038a4bc7_fk_sitetree_tree_id FOREIGN KEY (tree_id) REFERENCES public.sitetree_tree(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: staticscanresultsdb staticscanners_stati_project_id_f7551300_fk_project_i; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscanresultsdb
    ADD CONSTRAINT staticscanners_stati_project_id_f7551300_fk_project_i FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: staticscansdb staticscanners_staticscansdb_project_id_5bb9a0d6_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscansdb
    ADD CONSTRAINT staticscanners_staticscansdb_project_id_5bb9a0d6_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: staticscanresultsdb staticscanresultsdb_created_by_id_a4150f56_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscanresultsdb
    ADD CONSTRAINT staticscanresultsdb_created_by_id_a4150f56_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: staticscanresultsdb staticscanresultsdb_organization_id_be63a55f_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscanresultsdb
    ADD CONSTRAINT staticscanresultsdb_organization_id_be63a55f_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: staticscanresultsdb staticscanresultsdb_updated_by_id_97acf55d_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscanresultsdb
    ADD CONSTRAINT staticscanresultsdb_updated_by_id_97acf55d_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: staticscansdb staticscansdb_created_by_id_7186505b_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscansdb
    ADD CONSTRAINT staticscansdb_created_by_id_7186505b_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: staticscansdb staticscansdb_organization_id_c36cf550_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscansdb
    ADD CONSTRAINT staticscansdb_organization_id_c36cf550_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: staticscansdb staticscansdb_updated_by_id_a983d90d_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.staticscansdb
    ADD CONSTRAINT staticscansdb_updated_by_id_a983d90d_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: taskscheduledb taskscheduledb_created_by_id_e52428fa_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.taskscheduledb
    ADD CONSTRAINT taskscheduledb_created_by_id_e52428fa_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: taskscheduledb taskscheduledb_organization_id_c5c20b4c_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.taskscheduledb
    ADD CONSTRAINT taskscheduledb_organization_id_c5c20b4c_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: taskscheduledb taskscheduledb_updated_by_id_54509ac7_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.taskscheduledb
    ADD CONSTRAINT taskscheduledb_updated_by_id_54509ac7_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: token_blacklist_blacklistedtoken token_blacklist_blacklistedtoken_token_id_3cc7fe56_fk; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.token_blacklist_blacklistedtoken
    ADD CONSTRAINT token_blacklist_blacklistedtoken_token_id_3cc7fe56_fk FOREIGN KEY (token_id) REFERENCES public.token_blacklist_outstandingtoken(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: token_blacklist_outstandingtoken token_blacklist_outs_user_id_83bc629a_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.token_blacklist_outstandingtoken
    ADD CONSTRAINT token_blacklist_outs_user_id_83bc629a_fk_user_prof FOREIGN KEY (user_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_niktoresultdb tools_niktoresultdb_created_by_id_f67ad40a_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktoresultdb
    ADD CONSTRAINT tools_niktoresultdb_created_by_id_f67ad40a_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_niktoresultdb tools_niktoresultdb_organization_id_11163cad_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktoresultdb
    ADD CONSTRAINT tools_niktoresultdb_organization_id_11163cad_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_niktoresultdb tools_niktoresultdb_project_id_9755b23b_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktoresultdb
    ADD CONSTRAINT tools_niktoresultdb_project_id_9755b23b_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_niktoresultdb tools_niktoresultdb_updated_by_id_cbbe7768_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktoresultdb
    ADD CONSTRAINT tools_niktoresultdb_updated_by_id_cbbe7768_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_niktovulndb tools_niktovulndb_created_by_id_95854d18_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktovulndb
    ADD CONSTRAINT tools_niktovulndb_created_by_id_95854d18_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_niktovulndb tools_niktovulndb_organization_id_6215248c_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktovulndb
    ADD CONSTRAINT tools_niktovulndb_organization_id_6215248c_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_niktovulndb tools_niktovulndb_project_id_e123408c_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktovulndb
    ADD CONSTRAINT tools_niktovulndb_project_id_e123408c_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_niktovulndb tools_niktovulndb_updated_by_id_d6f07a25_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_niktovulndb
    ADD CONSTRAINT tools_niktovulndb_updated_by_id_d6f07a25_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_nmapresultdb tools_nmapresultdb_created_by_id_8e891749_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapresultdb
    ADD CONSTRAINT tools_nmapresultdb_created_by_id_8e891749_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_nmapresultdb tools_nmapresultdb_organization_id_5f8f289d_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapresultdb
    ADD CONSTRAINT tools_nmapresultdb_organization_id_5f8f289d_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_nmapresultdb tools_nmapresultdb_project_id_66621e3f_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapresultdb
    ADD CONSTRAINT tools_nmapresultdb_project_id_66621e3f_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_nmapresultdb tools_nmapresultdb_updated_by_id_4217a31a_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapresultdb
    ADD CONSTRAINT tools_nmapresultdb_updated_by_id_4217a31a_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_nmapscandb tools_nmapscandb_created_by_id_13003939_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapscandb
    ADD CONSTRAINT tools_nmapscandb_created_by_id_13003939_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_nmapscandb tools_nmapscandb_organization_id_8ff7ecb5_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapscandb
    ADD CONSTRAINT tools_nmapscandb_organization_id_8ff7ecb5_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_nmapscandb tools_nmapscandb_project_id_04432555_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapscandb
    ADD CONSTRAINT tools_nmapscandb_project_id_04432555_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_nmapscandb tools_nmapscandb_updated_by_id_c1523606_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapscandb
    ADD CONSTRAINT tools_nmapscandb_updated_by_id_c1523606_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_nmapvulnersportresultdb tools_nmapvulnerspor_nmapresultdb_ptr_id_ef4de882_fk_tools_nma; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_nmapvulnersportresultdb
    ADD CONSTRAINT tools_nmapvulnerspor_nmapresultdb_ptr_id_ef4de882_fk_tools_nma FOREIGN KEY (nmapresultdb_ptr_id) REFERENCES public.tools_nmapresultdb(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_sslscanresultdb tools_sslscanresultd_organization_id_d5960e4a_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_sslscanresultdb
    ADD CONSTRAINT tools_sslscanresultd_organization_id_d5960e4a_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_sslscanresultdb tools_sslscanresultdb_created_by_id_b4885d73_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_sslscanresultdb
    ADD CONSTRAINT tools_sslscanresultdb_created_by_id_b4885d73_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_sslscanresultdb tools_sslscanresultdb_project_id_4126175f_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_sslscanresultdb
    ADD CONSTRAINT tools_sslscanresultdb_project_id_4126175f_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: tools_sslscanresultdb tools_sslscanresultdb_updated_by_id_ae4abd7d_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.tools_sslscanresultdb
    ADD CONSTRAINT tools_sslscanresultdb_updated_by_id_ae4abd7d_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: unified_scan_config unified_scan_config_created_by_id_8566203f_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_config
    ADD CONSTRAINT unified_scan_config_created_by_id_8566203f_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: unified_scan_config unified_scan_config_organization_id_9f06312c_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_config
    ADD CONSTRAINT unified_scan_config_organization_id_9f06312c_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: unified_scan_config unified_scan_config_project_id_c108b478_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_config
    ADD CONSTRAINT unified_scan_config_project_id_c108b478_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: unified_scan_result unified_scan_result_created_by_id_a47e1412_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_result
    ADD CONSTRAINT unified_scan_result_created_by_id_a47e1412_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: unified_scan_result unified_scan_result_organization_id_1763d7fa_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_result
    ADD CONSTRAINT unified_scan_result_organization_id_1763d7fa_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: unified_scan_result unified_scan_result_project_id_ff279361_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_result
    ADD CONSTRAINT unified_scan_result_project_id_ff279361_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: unified_scan_summary unified_scan_summary_created_by_id_8de27a8f_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_summary
    ADD CONSTRAINT unified_scan_summary_created_by_id_8de27a8f_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: unified_scan_summary unified_scan_summary_organization_id_33040816_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_summary
    ADD CONSTRAINT unified_scan_summary_organization_id_33040816_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: unified_scan_summary unified_scan_summary_project_id_4de4fc41_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.unified_scan_summary
    ADD CONSTRAINT unified_scan_summary_project_id_4de4fc41_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_login_history user_login_history_user_id_44060508_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_login_history
    ADD CONSTRAINT user_login_history_user_id_44060508_fk_user_profile_id FOREIGN KEY (user_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_profile_groups user_profile_groups_group_id_864f8fbf_fk_auth_group_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_groups
    ADD CONSTRAINT user_profile_groups_group_id_864f8fbf_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_profile_groups user_profile_groups_userprofile_id_3e52d209_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_groups
    ADD CONSTRAINT user_profile_groups_userprofile_id_3e52d209_fk_user_profile_id FOREIGN KEY (userprofile_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_profile user_profile_organization_id_836b384f_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile
    ADD CONSTRAINT user_profile_organization_id_836b384f_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_profile user_profile_role_id_7f4a52a2_fk_user_roles_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile
    ADD CONSTRAINT user_profile_role_id_7f4a52a2_fk_user_roles_id FOREIGN KEY (role_id) REFERENCES public.user_roles(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_profile_user_permissions user_profile_user_pe_permission_id_f5abe73f_fk_auth_perm; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_user_permissions
    ADD CONSTRAINT user_profile_user_pe_permission_id_f5abe73f_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_profile_user_permissions user_profile_user_pe_userprofile_id_663dc0ea_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.user_profile_user_permissions
    ADD CONSTRAINT user_profile_user_pe_userprofile_id_663dc0ea_fk_user_prof FOREIGN KEY (userprofile_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanResultsdb webscanResultsdb_created_by_id_83b8eb6c_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public."webscanResultsdb"
    ADD CONSTRAINT "webscanResultsdb_created_by_id_83b8eb6c_fk_user_profile_id" FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanResultsdb webscanResultsdb_organization_id_f4197910_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public."webscanResultsdb"
    ADD CONSTRAINT "webscanResultsdb_organization_id_f4197910_fk_organization_id" FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanResultsdb webscanResultsdb_updated_by_id_bcaa5fd0_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public."webscanResultsdb"
    ADD CONSTRAINT "webscanResultsdb_updated_by_id_bcaa5fd0_fk_user_profile_id" FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscandb webscandb_created_by_id_48de06d3_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscandb
    ADD CONSTRAINT webscandb_created_by_id_48de06d3_fk_user_profile_id FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscandb webscandb_organization_id_be728f52_fk_organization_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscandb
    ADD CONSTRAINT webscandb_organization_id_be728f52_fk_organization_id FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscandb webscandb_updated_by_id_973472a0_fk_user_profile_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscandb
    ADD CONSTRAINT webscandb_updated_by_id_973472a0_fk_user_profile_id FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_burp_issue_definitions webscanners_burp_iss_created_by_id_6cdbccff_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_burp_issue_definitions
    ADD CONSTRAINT webscanners_burp_iss_created_by_id_6cdbccff_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_burp_issue_definitions webscanners_burp_iss_organization_id_49ebd2fb_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_burp_issue_definitions
    ADD CONSTRAINT webscanners_burp_iss_organization_id_49ebd2fb_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_burp_issue_definitions webscanners_burp_iss_updated_by_id_1c5ec145_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_burp_issue_definitions
    ADD CONSTRAINT webscanners_burp_iss_updated_by_id_1c5ec145_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_email_config_db webscanners_email_co_created_by_id_8d8dfad7_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_email_config_db
    ADD CONSTRAINT webscanners_email_co_created_by_id_8d8dfad7_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_email_config_db webscanners_email_co_organization_id_4e059e49_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_email_config_db
    ADD CONSTRAINT webscanners_email_co_organization_id_4e059e49_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_email_config_db webscanners_email_co_updated_by_id_727f109d_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_email_config_db
    ADD CONSTRAINT webscanners_email_co_updated_by_id_727f109d_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_task_schedule_db webscanners_task_sch_created_by_id_9f9f5c3a_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_task_schedule_db
    ADD CONSTRAINT webscanners_task_sch_created_by_id_9f9f5c3a_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_task_schedule_db webscanners_task_sch_organization_id_1d3ffe8e_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_task_schedule_db
    ADD CONSTRAINT webscanners_task_sch_organization_id_1d3ffe8e_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_task_schedule_db webscanners_task_sch_updated_by_id_854c5760_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_task_schedule_db
    ADD CONSTRAINT webscanners_task_sch_updated_by_id_854c5760_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_task_schedule_db webscanners_task_schedule_db_project_id_29b5865d_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_task_schedule_db
    ADD CONSTRAINT webscanners_task_schedule_db_project_id_29b5865d_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_web_scan_db webscanners_web_scan_created_by_id_24641621_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_web_scan_db
    ADD CONSTRAINT webscanners_web_scan_created_by_id_24641621_fk_user_prof FOREIGN KEY (created_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_web_scan_db webscanners_web_scan_db_project_id_bcee2505_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_web_scan_db
    ADD CONSTRAINT webscanners_web_scan_db_project_id_bcee2505_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_web_scan_db webscanners_web_scan_organization_id_32499307_fk_organizat; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_web_scan_db
    ADD CONSTRAINT webscanners_web_scan_organization_id_32499307_fk_organizat FOREIGN KEY (organization_id) REFERENCES public.organization(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanners_web_scan_db webscanners_web_scan_updated_by_id_9b793373_fk_user_prof; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscanners_web_scan_db
    ADD CONSTRAINT webscanners_web_scan_updated_by_id_9b793373_fk_user_prof FOREIGN KEY (updated_by_id) REFERENCES public.user_profile(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscanResultsdb webscanners_webscanresultsdb_project_id_de76b2dd_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public."webscanResultsdb"
    ADD CONSTRAINT webscanners_webscanresultsdb_project_id_de76b2dd_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webscandb webscanners_webscansdb_project_id_973109bc_fk_project_id; Type: FK CONSTRAINT; Schema: public; Owner: 131jCYxVFiKBJokuv2Kg4aWV9Ld
--

ALTER TABLE ONLY public.webscandb
    ADD CONSTRAINT webscanners_webscansdb_project_id_973109bc_fk_project_id FOREIGN KEY (project_id) REFERENCES public.project(id) DEFERRABLE INITIALLY DEFERRED;


--
-- PostgreSQL database dump complete
--

