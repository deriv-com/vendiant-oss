--
-- Vendiant core database schema (data-free)
--
-- Generated from a pg_dump of a running instance with all data rows,
-- ownership statements and sequence values removed. Loaded automatically by
-- docker-compose on first start of the postgres container. Tables for the
-- breach monitor, background scans and dashboard roles are created by the
-- backend on startup (Dashboard/db_migrations.py and the service classes).
-- To apply manually:
--   psql -U <db_user> -d <db_name> -f Postgress/init-scripts/schema.sql
--


-- Dumped from database version 15.14
-- Dumped by pg_dump version 15.14

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

--
-- Name: cleanup_old_audit_logs_with_counter(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cleanup_old_audit_logs_with_counter() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    counter_value BIGINT;
    deleted_count INTEGER;
    cutoff_date TIMESTAMP WITH TIME ZONE;
BEGIN
    -- Increment the counter
    counter_value := nextval('audit_logs_insert_counter');
    
    -- Only run cleanup every 5000 inserts
    IF counter_value % 5000 = 0 THEN
        cutoff_date := CURRENT_TIMESTAMP - INTERVAL '365 days';
        
        -- Delete old records
        DELETE FROM audit_logs 
        WHERE created_at < cutoff_date;
        
        GET DIAGNOSTICS deleted_count = ROW_COUNT;
        
        IF deleted_count > 0 THEN
            RAISE NOTICE 'Audit logs cleanup (counter method): Deleted % records older than % at insert #%', 
                        deleted_count, cutoff_date, counter_value;
        END IF;
        
        -- Reset counter periodically to prevent overflow
        IF counter_value >= 1000000 THEN
            ALTER SEQUENCE audit_logs_insert_counter RESTART WITH 1;
            RAISE NOTICE 'Reset audit logs insert counter at %', counter_value;
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$;


--
-- Name: cleanup_old_news(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cleanup_old_news() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM public.news
    WHERE created_at < NOW() - INTERVAL '1 year';
    RETURN NULL;
END;
$$;


--
-- Name: comprehensive_cleanup(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.comprehensive_cleanup() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Clean up both tables whenever either is modified
    DELETE FROM scores WHERE updated_at < NOW() - INTERVAL '3 months';
    DELETE FROM vulnerabilities WHERE detected_at < NOW() - INTERVAL '3 months';
    
    -- Log cleanup activity (optional)
    RAISE NOTICE 'Cleanup completed: removed records older than 3 months from scores and vulnerabilities tables';
    
    RETURN COALESCE(NEW, OLD);
END;
$$;


--
-- Name: log_audit_action(character varying, character varying, character varying, character varying, character varying, character varying, character varying, jsonb, inet, text, character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.log_audit_action(p_user_id character varying, p_user_name character varying, p_user_role character varying, p_action character varying, p_resource_type character varying DEFAULT NULL::character varying, p_resource_id character varying DEFAULT NULL::character varying, p_resource_name character varying DEFAULT NULL::character varying, p_details jsonb DEFAULT NULL::jsonb, p_ip_address inet DEFAULT NULL::inet, p_user_agent text DEFAULT NULL::text, p_session_id character varying DEFAULT NULL::character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO audit_logs (
        user_id, user_name, user_role, action, resource_type, 
        resource_id, resource_name, details, ip_address, 
        user_agent, session_id
    ) VALUES (
        p_user_id, p_user_name, p_user_role, p_action, p_resource_type,
        p_resource_id, p_resource_name, p_details, p_ip_address,
        p_user_agent, p_session_id
    );
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_groups (
    id integer NOT NULL,
    group_name character varying(120) NOT NULL,
    description text,
    permissions jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: access_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.access_groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: access_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.access_groups_id_seq OWNED BY public.access_groups.id;


--
-- Name: api_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_credentials (
    id integer NOT NULL,
    credential_hash character varying(255) NOT NULL,
    credential_prefix character varying(20) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    request_limit integer DEFAULT 5000,
    is_enabled boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_accessed timestamp without time zone,
    expires_at timestamp without time zone,
    created_by character varying(255),
    config jsonb DEFAULT '{}'::jsonb,
    group_name character varying(120) DEFAULT 'read_only'::character varying NOT NULL,
    assigned_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    assigned_by character varying(255),
    access_type character varying(20) DEFAULT 'temporary'::character varying NOT NULL,
    CONSTRAINT api_credentials_access_type_check CHECK (((access_type)::text = ANY (ARRAY[('temporary'::character varying)::text, ('permanent'::character varying)::text])))
);


--
-- Name: COLUMN api_credentials.group_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.api_credentials.group_name IS 'Permission group (read_only, admin)';


--
-- Name: COLUMN api_credentials.assigned_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.api_credentials.assigned_at IS 'When the group was assigned to this credential';


--
-- Name: COLUMN api_credentials.assigned_by; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.api_credentials.assigned_by IS 'Who assigned the group to this credential';


--
-- Name: api_credentials_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.api_credentials_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: api_credentials_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.api_credentials_id_seq OWNED BY public.api_credentials.id;


--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
    id integer NOT NULL,
    user_id text NOT NULL,
    user_name text,
    user_email text NOT NULL,
    user_role text,
    action text NOT NULL,
    resource_type text,
    resource_id text,
    details jsonb,
    ip_address inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    slack_alert_sent_at TIMESTAMP
);


--
-- Name: audit_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_logs_id_seq OWNED BY public.audit_logs.id;


--
-- Name: audit_logs_insert_counter; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_logs_insert_counter
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: breach_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.breach_records (
    id integer NOT NULL,
    uuid text NOT NULL,
    email text NOT NULL,
    password_leaked integer NOT NULL,
    passwords jsonb NOT NULL,
    severity text,
    status text,
    description text,
    created_at timestamp without time zone,
    resolved_at timestamp without time zone,
    slack_alert_sent_at TIMESTAMP
);


--
-- Name: breach_records_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.breach_records_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: breach_records_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.breach_records_id_seq OWNED BY public.breach_records.id;


--
-- Name: excluded_subdomains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.excluded_subdomains (
    id integer NOT NULL,
    vendor_id integer NOT NULL,
    domain text NOT NULL,
    subdomain text NOT NULL,
    excluded_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: excluded_subdomains_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.excluded_subdomains_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: excluded_subdomains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.excluded_subdomains_id_seq OWNED BY public.excluded_subdomains.id;


--
-- Name: news; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.news (
    id integer NOT NULL,
    domain text NOT NULL,
    event_date date NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    severity character varying(20) NOT NULL,
    source_url text NOT NULL,
    event_type character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    slack_alert_sent_at TIMESTAMP,
    CONSTRAINT news_event_type_check CHECK (((event_type)::text = ANY (ARRAY[('Incident'::character varying)::text, ('News'::character varying)::text]))),
    CONSTRAINT news_severity_check CHECK (((severity)::text = ANY (ARRAY[('Low'::character varying)::text, ('Medium'::character varying)::text, ('High'::character varying)::text, ('Critical'::character varying)::text, ('Info'::character varying)::text])))
);


--
-- Name: news_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.news_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: news_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.news_id_seq OWNED BY public.news.id;


--
-- Name: request_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.request_audit_log (
    id integer NOT NULL,
    credential_id integer,
    key_name character varying(255),
    action character varying(60),
    client_ip inet,
    user_agent text,
    request_data jsonb,
    "timestamp" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    response_code integer,
    success boolean,
    endpoint_path text,
    http_method text,
    request_hash text,
    request_summary text,
    slack_alert_sent_at TIMESTAMP
);


--
-- Name: COLUMN request_audit_log.key_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.request_audit_log.key_name IS 'Name of the API key used for the request (for easier identification)';


--
-- Name: request_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.request_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: request_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.request_audit_log_id_seq OWNED BY public.request_audit_log.id;


--
-- Name: scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scores (
    id integer NOT NULL,
    vendor_id integer NOT NULL,
    domain text NOT NULL,
    score_category text NOT NULL,
    time_period text NOT NULL,
    score integer,
    updated_at timestamp without time zone DEFAULT now(),
    scan_format text DEFAULT 'individual_scan'::text,
    CONSTRAINT scan_format_valid CHECK ((scan_format = ANY (ARRAY['full_scan_all'::text, 'new_vendor'::text, 'full_scan_single'::text, 'individual_scan'::text, 'filtered_scan'::text]))),
    CONSTRAINT scores_score_category_check CHECK ((score_category = ANY (ARRAY['Website'::text, 'Domain Reputation'::text, 'Encryption'::text, 'DNS'::text, 'Network'::text, 'Email'::text, 'Overall'::text]))),
    CONSTRAINT scores_time_period_check CHECK ((time_period = ANY (ARRAY['current'::text, '1month'::text, '3months'::text, '12months'::text])))
);


--
-- Name: scores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scores_id_seq OWNED BY public.scores.id;


--
-- Name: subdomains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subdomains (
    id integer NOT NULL,
    domain text NOT NULL,
    vendor_id integer NOT NULL,
    status text NOT NULL,
    subdomain text,
    manually_added boolean DEFAULT false,
    manually_added_at timestamp without time zone,
    CONSTRAINT subdomains_status_check CHECK ((status = ANY (ARRAY['Active'::text, 'Inactive'::text])))
);


--
-- Name: COLUMN subdomains.manually_added; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.subdomains.manually_added IS 'Indicates if this subdomain was manually added by a user (TRUE) or discovered automatically (FALSE)';


--
-- Name: COLUMN subdomains.manually_added_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.subdomains.manually_added_at IS 'Timestamp when the subdomain was manually added';


--
-- Name: subdomains_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.subdomains_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: subdomains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.subdomains_id_seq OWNED BY public.subdomains.id;


--
-- Name: vendors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vendors (
    id integer NOT NULL,
    vendor_name text NOT NULL,
    domain text NOT NULL,
    grade text DEFAULT 'N/A'::text,
    added_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_scanned timestamp without time zone,
    overall_score_current integer,
    overall_score_1month integer,
    overall_score_3months integer,
    overall_score_12months integer,
    subdomain_count integer DEFAULT 0,
    trend integer,
    certifications text DEFAULT 'None'::text,
    portfolio text,
    tier text,
    industry text,
    additional_domains jsonb DEFAULT '[]'::jsonb,
    low_score_alert_sent_at TIMESTAMP
);


--
-- Name: vendors_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vendors_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vendors_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vendors_id_seq OWNED BY public.vendors.id;


--
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerabilities (
    id integer NOT NULL,
    vendor_id integer NOT NULL,
    domain text NOT NULL,
    subdomain text,
    score_category text NOT NULL,
    title text NOT NULL,
    description text,
    severity text NOT NULL,
    detected_at timestamp without time zone DEFAULT now(),
    slack_alert_sent_at TIMESTAMP,
    CONSTRAINT vulnerabilities_score_category_check CHECK ((score_category = ANY (ARRAY['Website'::text, 'Domain Reputation'::text, 'Encryption'::text, 'DNS'::text, 'Network'::text, 'Email'::text]))),
    CONSTRAINT vulnerabilities_severity_check CHECK ((severity = ANY (ARRAY['Info'::text, 'Low'::text, 'Medium'::text, 'High'::text, 'Critical'::text])))
);


--
-- Name: vulnerabilities_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vulnerabilities_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulnerabilities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vulnerabilities_id_seq OWNED BY public.vulnerabilities.id;


--
-- Name: access_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_groups ALTER COLUMN id SET DEFAULT nextval('public.access_groups_id_seq'::regclass);


--
-- Name: api_credentials id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_credentials ALTER COLUMN id SET DEFAULT nextval('public.api_credentials_id_seq'::regclass);


--
-- Name: audit_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs ALTER COLUMN id SET DEFAULT nextval('public.audit_logs_id_seq'::regclass);


--
-- Name: breach_records id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_records ALTER COLUMN id SET DEFAULT nextval('public.breach_records_id_seq'::regclass);


--
-- Name: excluded_subdomains id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.excluded_subdomains ALTER COLUMN id SET DEFAULT nextval('public.excluded_subdomains_id_seq'::regclass);


--
-- Name: news id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.news ALTER COLUMN id SET DEFAULT nextval('public.news_id_seq'::regclass);


--
-- Name: request_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_audit_log ALTER COLUMN id SET DEFAULT nextval('public.request_audit_log_id_seq'::regclass);


--
-- Name: scores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scores ALTER COLUMN id SET DEFAULT nextval('public.scores_id_seq'::regclass);


--
-- Name: subdomains id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subdomains ALTER COLUMN id SET DEFAULT nextval('public.subdomains_id_seq'::regclass);


--
-- Name: vendors id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vendors ALTER COLUMN id SET DEFAULT nextval('public.vendors_id_seq'::regclass);


--
-- Name: vulnerabilities id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities ALTER COLUMN id SET DEFAULT nextval('public.vulnerabilities_id_seq'::regclass);


--
-- Data for Name: access_groups; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: api_credentials; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: audit_logs; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: breach_records; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: excluded_subdomains; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: news; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: request_audit_log; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: scores; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: subdomains; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: vendors; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Data for Name: vulnerabilities; Type: TABLE DATA; Schema: public; Owner: -
--


--
-- Name: access_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: api_credentials_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: audit_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: audit_logs_insert_counter; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: breach_records_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: excluded_subdomains_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: news_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: request_audit_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: scores_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: subdomains_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: vendors_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: vulnerabilities_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--


--
-- Name: access_groups access_groups_group_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_groups
    ADD CONSTRAINT access_groups_group_name_key UNIQUE (group_name);


--
-- Name: access_groups access_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_groups
    ADD CONSTRAINT access_groups_pkey PRIMARY KEY (id);


--
-- Name: api_credentials api_credentials_credential_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_credentials
    ADD CONSTRAINT api_credentials_credential_hash_key UNIQUE (credential_hash);


--
-- Name: api_credentials api_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_credentials
    ADD CONSTRAINT api_credentials_pkey PRIMARY KEY (id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: breach_records breach_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_records
    ADD CONSTRAINT breach_records_pkey PRIMARY KEY (id);


--
-- Name: breach_records breach_records_uuid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_records
    ADD CONSTRAINT breach_records_uuid_key UNIQUE (uuid);


--
-- Name: excluded_subdomains excluded_subdomains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.excluded_subdomains
    ADD CONSTRAINT excluded_subdomains_pkey PRIMARY KEY (id);


--
-- Name: excluded_subdomains excluded_subdomains_vendor_id_subdomain_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.excluded_subdomains
    ADD CONSTRAINT excluded_subdomains_vendor_id_subdomain_key UNIQUE (vendor_id, subdomain);


--
-- Name: news news_domain_title_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.news
    ADD CONSTRAINT news_domain_title_key UNIQUE (domain, title);


--
-- Name: news news_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.news
    ADD CONSTRAINT news_pkey PRIMARY KEY (id);


--
-- Name: request_audit_log request_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_audit_log
    ADD CONSTRAINT request_audit_log_pkey PRIMARY KEY (id);


--
-- Name: scores scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scores
    ADD CONSTRAINT scores_pkey PRIMARY KEY (id);


--
-- Name: scores scores_vendor_id_domain_score_category_updated_at_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scores
    ADD CONSTRAINT scores_vendor_id_domain_score_category_updated_at_key UNIQUE (vendor_id, domain, score_category, updated_at);


--
-- Name: subdomains subdomains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subdomains
    ADD CONSTRAINT subdomains_pkey PRIMARY KEY (id);


--
-- Name: subdomains subdomains_vendor_id_subdomain_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subdomains
    ADD CONSTRAINT subdomains_vendor_id_subdomain_key UNIQUE (vendor_id, subdomain);


--
-- Name: vendors vendors_domain_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vendors
    ADD CONSTRAINT vendors_domain_key UNIQUE (domain);


--
-- Name: vendors vendors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vendors
    ADD CONSTRAINT vendors_pkey PRIMARY KEY (id);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: idx_api_credentials_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_credentials_enabled ON public.api_credentials USING btree (is_enabled);


--
-- Name: idx_api_credentials_group_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_credentials_group_name ON public.api_credentials USING btree (group_name);


--
-- Name: idx_api_credentials_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_credentials_hash ON public.api_credentials USING btree (credential_hash);


--
-- Name: idx_api_credentials_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_credentials_prefix ON public.api_credentials USING btree (credential_prefix);


--
-- Name: idx_audit_logs_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_action ON public.audit_logs USING btree (action);


--
-- Name: idx_audit_logs_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_created_at ON public.audit_logs USING btree (created_at DESC);


--
-- Name: idx_audit_logs_resource_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_resource_type ON public.audit_logs USING btree (resource_type);


--
-- Name: idx_audit_logs_user_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_user_email ON public.audit_logs USING btree (user_email);


--
-- Name: idx_request_audit_log_credential_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_request_audit_log_credential_id ON public.request_audit_log USING btree (credential_id);


--
-- Name: idx_request_audit_log_endpoint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_request_audit_log_endpoint ON public.request_audit_log USING btree (endpoint_path);


--
-- Name: idx_request_audit_log_key_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_request_audit_log_key_name ON public.request_audit_log USING btree (key_name);


--
-- Name: idx_request_audit_log_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_request_audit_log_timestamp ON public.request_audit_log USING btree ("timestamp");


--
-- Name: idx_subdomains_manually_added; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_subdomains_manually_added ON public.subdomains USING btree (manually_added) WHERE (manually_added = true);


--
-- Name: audit_logs audit_logs_cleanup_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_logs_cleanup_trigger AFTER INSERT ON public.audit_logs FOR EACH ROW EXECUTE FUNCTION public.cleanup_old_audit_logs_with_counter();


--
-- Name: scores trigger_comprehensive_cleanup_scores; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_comprehensive_cleanup_scores AFTER INSERT OR UPDATE ON public.scores FOR EACH STATEMENT EXECUTE FUNCTION public.comprehensive_cleanup();


--
-- Name: vulnerabilities trigger_comprehensive_cleanup_vulnerabilities; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_comprehensive_cleanup_vulnerabilities AFTER INSERT OR UPDATE ON public.vulnerabilities FOR EACH STATEMENT EXECUTE FUNCTION public.comprehensive_cleanup();


--
-- Name: excluded_subdomains excluded_subdomains_domain_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.excluded_subdomains
    ADD CONSTRAINT excluded_subdomains_domain_fkey FOREIGN KEY (domain) REFERENCES public.vendors(domain) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: excluded_subdomains excluded_subdomains_vendor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.excluded_subdomains
    ADD CONSTRAINT excluded_subdomains_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id) ON DELETE CASCADE;


--
-- Name: news news_domain_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.news
    ADD CONSTRAINT news_domain_fkey FOREIGN KEY (domain) REFERENCES public.vendors(domain) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: request_audit_log request_audit_log_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_audit_log
    ADD CONSTRAINT request_audit_log_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.api_credentials(id) ON DELETE CASCADE;


--
-- Name: scores scores_domain_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scores
    ADD CONSTRAINT scores_domain_fkey FOREIGN KEY (domain) REFERENCES public.vendors(domain) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: scores scores_vendor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scores
    ADD CONSTRAINT scores_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id) ON DELETE CASCADE;


--
-- Name: subdomains subdomains_domain_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subdomains
    ADD CONSTRAINT subdomains_domain_fkey FOREIGN KEY (domain) REFERENCES public.vendors(domain) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: subdomains subdomains_vendor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subdomains
    ADD CONSTRAINT subdomains_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id) ON DELETE CASCADE;


--
-- Name: vulnerabilities vulnerabilities_domain_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_domain_fkey FOREIGN KEY (domain) REFERENCES public.vendors(domain) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: vulnerabilities vulnerabilities_vendor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--




--
-- Seed data required by the API layer
--

INSERT INTO public.access_groups (group_name, description, permissions) VALUES
('read_only', 'Read-only access to domain reports and risk scores', '{"vendors": ["read"], "reports": ["read"]}'),
('admin', 'Full access to all resources including API key management', '{"vendors": ["read"], "reports": ["read"], "auth": ["read", "create", "delete"], "audit": ["read"]}')
ON CONFLICT (group_name) DO NOTHING;
