/*
 * Copyright (C) 2008 Ideas2IT Technologies Pte Ltd. (http://www.ideas2it.com/).
 */

package com.coherent.unnamed.auth.constant;

import java.util.regex.Pattern;

/**
 * <p>
 * To define the common static parameter used all over the application.
 * </p>
 *
 * @author Nagarajan created on May 30, 2019
 *
 */
public final class Constants {
	public static final int ERROR_CODE= 500;
	public static final String INVALID = "Invalid mailID";
	public static final String INVALID1 = "Invalid OTP Or mailID";
	public static final String MAILID = "noreply@coherent.in";
	public static final String OTP_MSG = "Login OTP message";
	public static final String MAIL_OTP_MSG ="This OTP Number is for Login.OTP number is ";
	public static final String SUCCESS ="OTP sent successfully";
	public static final String SUCCESS1 ="OTP Resented successfully";

    public static final String USER_TOKEN = "user_token";
    public static final Object ONE = 1;
    public static final String USER_NAME = "username";
	public static final String AD = "ad";
	public static final Pattern VALID_EMAIL_ADDRESS_REGEX =
			Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);
	public static final String URL = "/swagger-ui.html";
	public static final String COHERENT = "@coherent.in";
    public static final Object ZERO = 0;

    private Constants() {};
	
	public static final String PRODUCT_ID = "product_id";
	public static final String DISCHARGE_PORT = "DischargePort";
	public static final String KEY_INCOTERMS = "IncoTerms";
	public static final String TABLE_STATUS = "Status";
	public static final String TABLE_PAYMENT_TERM = "PaymentTerm";
	public static final String TABLE_SHIPMENT_TYPE = "ShipmentType";
	public static final String TABLE_CUSTOMER = "customer";
	public static final String TABLE_CONTRACT = "contract";
	public static final String TABLE_MENU = "menu";
	public static final String MENU_URL = "menu_url";
	public static final Boolean BOOLEAN_TRUE = Boolean.TRUE;
	public static final Boolean BOOLEAN_FALSE = Boolean.FALSE;
	public static final String IS_ALL = "isAll";

	public static final String PACKAGE_RMS = "com.coherent.unnamed";
	public static final String OLAM_SEAGULL_LOGGER = "OlamSeagullLogger";
	public static final int INACTIVE_SESSION_EXPIRE_HOURS = 5;

	//Common Symbols & Strings
	public static final String SPACE = " ";
	public static final String EMPTY = "";
	public static final String OPEN_BRACKET = "[";
	public static final String CLOSE_BRACKET = "]";
	public static final String OPEN_BRACE = "{";
	public static final String CLOSE_BRACE = "}";
	public static final String HYPHEN = "-";
	public static final String ASTERISK_SYMBOL = "*";
	public static final String FORWARD_SLASH = "/";
	public static final String APPROVED = "approved";
	public static final String STRING_NULL = null;
	public static final String KEY_TYPES = "types";
	public static final String UNDERSCORE = "_";
	public static final String LOCATION = "location";
	public static final String PRIORITY = "priority";
	public static final String MONTHYEAR = "monthYear";
	public static final String PARENTID = "parentId";
	public static final String ISVENDOR = "isVendor";
	public static final String RESULT_LIST = "resultList";
	public static final String COMMA = ",";
	public static final String EQUALS = "=";
	public static final String FOR_INVOICE_NUMBER = " for invoice number : " ;
	public static final String EVENT_ID = "event_id";
	public static final Object PUSH_NOTIFICATION_BODY = "pushNotificationBody";
	public static final Object PUSH_NOTIFICATION_TITLE = "pushNotificationTitle";
	public static final String APPROVAL_ID = "approval_id";
	public static final String BOLD_OPEN_TAG = "<b>";
	public static final String BOLD_CLOSE_TAG = "</b>";
	public static final String AND = "and";
	

	public static final String COMPANY = "company";
	// Spring Components and warning
	public static final String SERIAL = "serial";
	public static final String ERROR_MESSAGE_PROPERTY = "classpath:error_messages.properties";
	public static final String RAWTYPES = "rawtypes";
	public static final String UNCHECKED = "unchecked";
	public static final String UNUSED = "unused";
	public static final String PASSWORDENCODER = "passwordEncoder";
	public static final String TEMPLATE_MESSAGE_PROPERTY = "classpath:template_message.properties";

	//Date Formate
	public static final String JSON_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
	public static final String CURRENT_TIMESTAMP_DATE_FORMAT = "yyyy.MM.dd.HH.mm.ss";
	public static final String TEN_DIGITS_DECIMAL_FORMAT = "#.##########";
	public static final String COMMON_DATE_FORMAT = "yyyy-MM-dd";
	public static final String WEEK = "WEEK";
	public static final String DATE = "DATE";
	public static final String DATE_COLUMN = "date";
	public static final String DAY 	= "DAY";
	public static final String MONTH = "MONTH";
	public static final String YEARS = "YEARS";
	public static final String TRUE = "true";
	public static final String END 	= "End";
	public static final String BEGIN = "Begin";
	public static final String DATE_FORMAT_YYYY_MM_DD = "yyyy-MM-dd";
	public static final String MMM_YY_FORMAT = "MMM-yy";
	public static final String DD_MM_YYYY = "dd-mm-yyyy";

	//Entity Fields
	public static final String ID = "id";
	public static final String BUSINESS_ID = "businessUnitId";
	public static final String CREATED_BY = "created_by";
	public static final String MODIFIED_BY = "modified_by";
	public static final String CREATED_AT = "created_at";
	public static final String MODIFIED_AT = "modified_at";
	public static final String UPDATED_BY = "updated_by"; 
	public static final String UPDATED_AT = "updated_at";
	public static final String NAME = "name";
	public static final String DESCRIPTION = "description";
	public static final String IS_ACTIVE = "is_active";
	public static final String ACTIVE = "active";
	public static final String USERNAME = "username";
	public static final String USERNAME_KEY = "userName";
	public static final String PASSWORD = "password";
	public static final String EMPLOYEE_ID = "employee_id";
	public static final String TIMESHEET_ROLE_ID = "timesheet_role_id";
	public static final String START_DATE = "start_date";
	public static final String END_DATE = "end_date";
	public static final String BILLABLE_TYPE = "billable_type";
	public static final String PROJECT_ID = "project_id";
	public static final String PROJECT = "project";
	public static final String EMPLOYEE = "employee";
	public static final String USER_ROLE = "userRole";
	public static final String USER_ID = "user_id_fk";
	public static final String ROLE_ID = "role_id";
	public static final String ROLES = "roles";
	public static final String ACCOUNT_EXPIRED = "account_expired";
	public static final String ACCOUNT_LOCKED = "account_locked";
	public static final String CREDENTIALS_EXPIRED = "credentials_expired";
	public static final String CODE = "code";
	public static final String PARENT_ID = "parent_id";
	public static final String BUSINESS_UNIT_ID = "business_unit_id";
	public static final String TYPE = "type";
	public static final String STATUS = "status";
	public static final String FILE_NAME = "file_name";
	public static final String FORMAT = "formate";
	public static final String ITEM_ID = "item_id";
	public static final String ITEM_TYPE = "item_type";
	public static final String CURRENCY_ID  = "currency_id";
	public static final String BU_HEAD = "buHead";
	public static final String BUSINESS_UNIT = "businessUnit";
	public static final String CURRENCY = "currency";
	public static final String MENU_ID = "menu_id";
    public static final String PERMISSION = "permission";
    public static final String ROLE = "role";
    public static final String BODY = "body";
    public static final String LEVEL = "level";
    public static final String ROLEID = "roleId";
    public static final String VERSION = "version";
    public static final String USERID = "userId";
    public static final String COUNTRY ="country";
    
    public static final String MESSAGE = "message";
    public static final String TO_EMAIL = "to_mail";
    public static final String CC_EMAILS = "cc_mail";
    public static final String BCC_EMAILS = "bcc_emails";
    public static final String SUBJECT = "subject"; 
    public static final String CONTENT_TYPE = "content_type";
    public static final String PARAMS = "params";
    public static final String COUNT = "count";
	public static final String ITEM = "item";
	public static final String PREFIX = "prefix";
	
	
	public static final String ADDRESS = "address";
	public static final String MOBILE_NUMBER = "mobile_number";
	public static final String DEVICE_TOKEN = "device_token";
	public static final String IMAGE_URL = "image_url";
	public static final String DEVICE_TYPE = "device_type";
	public static final String DEVICE_ID = "device_id";
	
	public static final String EMAIL = "email";
	public static final String DOCUMENT_URL = "document_url";
	
	public static final String LOCATION_ID = "location_id";
	public static final String AMOUNT = "amount";
	public static final String COUNTRY_ID = "country_id";

	//Entity Table names
	public static final String TABLE_ROLE = "role";
	public static final String TABLE_USER = "user";
	public static final String TABLE_USER_ROLE = "user_role";
	public static final String TABLE_DOCUMENT = "document";
	public static final String TABLE_BILLING_TYPE = "billing_type";
	public static final String TABLE_CURRENCY = "currency";
	public static final String TABLE_USER_ROLE_PERMISSION = "user_role_permission";
	public static final String TABLE_NOTIFICATION = "notification";
	public static final String TABLE_EMAIL_TEMPLATE = "email_template";
	public static final String TABLE_LOCATION = "location";
	public static final String TABLE_COUNTRY = "country";
	public static final String DEPARTMENT = "department";
	public static final String TABLE_PRODUCT_TYPE = "product_type";
	public static final String TABLE_PRODUCT = "product";
	public static final String TABLE_PORT = "port";
	public static final String TABLE_INCOTERMS = "incoterms";
	public static final String TABLE_CONTRACT_STATUS = "contract_status";
	public static final String TABLE_PRODUCT_INFO = "product_info";
	public static final String TABLE_PACKAGE_TYPE = "package_type";
	public static final String TABLE_SHIPMENT = "shipment";
	public static final String TABLE_SHIPMENT_VESSEL_DETAIL = "shipment_vessel_detail";
	public static final String TABLE_SHIPMENT_VESSEL_PRODUCT_DETAIL = "shipment_vessel_product_detail";
	public static final String TABLE_SHIPMENT_VESSEL_LOADING_DETAIL = "shipment_vessel_loading_detail";
	public static final String TABLE_SHIPMENT_VESSEL_QUANTITY_DETAIL = "shipment_vessel_quantity_detail";
	public static final String TABLE_SHIPMENT_VESSEL_LOAD_QUANTITY_DETAIL = "shipment_vessel_load_quantity_detail";
	public static final String TABLE_PAYMENT_BOL = "payment_bol";
	public static final String TABLE_PAYMENT_CREDIT_DEBIT_NOTE = "payment_credit_debit_note";
	public static final String TABLE_PAYMENT_DETAIL = "payment_detail";
	public static final String TABLE_CURRENCY_COVER = "currency_cover";
	public static final String TABLE_PAYMENT = "payment";
	public static final String TABLE_CUSTOMER_CONTACT_DETAILS = "customer_contact_details";
	public static final String TABLE_PAYMENT_TERMS = "payment_terms";
	
	//Column Definition
	public static final String COLUMN_DEFINITION_LONGBLOB = "LONGBLOB";

	//AESKEY
	public static final String AES_KEY = "OL@MZEU$0(8&";

	public static final String ADVANCE_AMOUNT = "advance_amount";
	public static final String TOTAL_CONTRACT_VALUE = "total_contract_value";
	//Column Transformer
	public static final String COLUMN_TRANSFORMER_READ_AES_PASSWORD = "AES_DECRYPT("+PASSWORD+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_ADVANCE_AMOUNT = "AES_DECRYPT("+ADVANCE_AMOUNT+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_TOTAL_CONTRACT_VALUE = "AES_DECRYPT("+TOTAL_CONTRACT_VALUE+", '"+AES_KEY+"')";

	public static final String COLUMN_TRANSFORMER_READ_AES_AMOUNT = "AES_DECRYPT("+AMOUNT+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_WRITE_AES = "AES_ENCRYPT(?, '"+AES_KEY+"')";


	public static final String TABLE_PREFIX = "prefix";
	//Map keys
	public static final String KEY_PERMISSION = "permission";
	public static final String KEY_MENU_URL = "menuUrl";
	public static final String KEY_PARENT_MENU = "parentMenu";
	public static final String KEY_PARENT_MENU_URL = "parentMenuUrl";
	public static final String KEY_BUSINESS_UNITS = "businessUnits";


	//Email
	public static final String NOTIFICAION_TYPE_EMAIL = "email";
	public static final String NOTIFICAION_TYPE_MESSAGE = "message";
	public static final String NOTIFICAION_STATUS_PENDING = "pending";
	public static final String NOTIFICAION_STATUS_PROCESSED = "processed";
	public static final String NOTIFICAION_STATUS_FAILED = "failed";
	public static final String PROJECT_APPROVED="Approved";
	public static final String PROJECT_REJECTED="Rejected";
	public static final String TIMESHEET_SHEET_REMINDER="Timesheet Sheet Reminder";
	public static final String ERROR = "ERROR";

	//Message validation file type
	public static final String SUCCES = "SUCCESS";
	public static final String ENUM_KEY_CREATE = "CREATE";
	public static final String ENUM_KEY_EDIT = "EDIT";
	public static final String ENUM_KEY_VIEW = "VIEW";
	public static final String ENUM_KEY_LIST = "LIST";
	public static final String ENUM_KEY_DELETE = "DELETE";
	public static final String ENUM_KEY_APPROVE = "APPROVE";
	public static final String ENUM_KEY_REPORT = "REPORT";
	public static final String ENUM_KEY_EXTEND = "EXTEND";
	public static final String ENUM_KEY_SEND_NOTIFICATION = "SEND_NOTIFICATION";
	public static final String ENUM_KEY_TEAM_REPORT = "TEAM_REPORT";
	public static final String ENUM_KEY_TEAM_APPROVAL = "TEAM_APPROVAL";
	public static final String ENUM_KEY_SEND_APPROVAL = "SEND_APPROVAL";
	public static final String ENUM_KEY_DOCUMENT_UPLOAD = "DOCUMENT_UPLOAD";
	public static final String ENUM_KEY_INTERNAL_ORDER = "INTERNAL_ORDER";
	public static final String ENUM_KEY_APPROVAL = "APPROVAL";
	public static final String ENUM_KEY_MONTHLY_APPROVAL = "MONTHLY_APPROVAL";
	public static final String ENUM_KEY_INTERNAL_ORDER_EDIT = "INTERNAL_ORDER_EDIT";
	public static final String ENUM_KEY_OFF_BOARD = "OFF_BOARD";
	public static final String ENUM_KEY_DUPLICATE = "DUPLICATE";
	public static final String ENUM_KEY_SCHEDULE_INTERVIEW = "SCHEDULE_INTERVIEW";
	public static final String ENUM_KEY_SWAP = "SWAP";
	public static final String ENUM_KEY_SEND_TO_VENDOR = "SEND_TO_VENDOR";
	public static final String ENUM_KEY_SEND_TO_PM = "SEND_TO_PM";
	public static final String ENUM_KEY_ON_BOARD = "ON_BOARD";
	public static final String ENUM_KEY_REJECT = "REJECT";
	public static final String ENUM_SEND_TO_RM = "SEND_TO_RM";
	public static final String ENUM_ADD_PROFILE = "ADD_PROFILE";
	public static final String ENUM_SEND_PROFILE = "SEND_PROFILE";
	public static final String ENUM_UPLOAD_RESUME = "UPLOAD_RESUME";
	public static final String ENUM_KEY_INVOICE = "Invoice";
	public static final String ENUM_KEY_REMAINDER = "remainder";
	public static final String ENUM_EXTENSION_LIST = "EXTENSION_LIST";
	public static final String ENUM_DH_APPROVE = "DH_APPROVE";
	public static final String ENUM_DH_REJECT = "DH_REJECT";
	public static final String ENUM_VENDOR_APPROVE = "VENDOR_APPROVE";
	public static final String ENUM_VENDOR_REJECT = "VENDOR_REJECT";
	public static final String ENUM_INITIATE = "INITIATE";


	public static final String HOUR_SEPERATOR = ":";
	public static final String DOT= ".";

	//send mail
	public static final String ERROR_EMAIL = "Error while sending email: ";
	public static final String WEB_NOTIFICATION_LIMIT = "20";

	public static final String TEMPLATE_INFO = "INFO";


	public static final String STATUS_CLOSED = "Closed";
	public static final String MAIL_SUFFIX = "@olamnet.com";
	public static final String CANDIDATE_INITIATED = "initiatedRM";

	public static final String SELECTED = "Selected";
	public static final String REJECTED = "Rejected";
	public static final String CONSULTANT = "consultant";
	public static final String NOT_VALID_ACTION ="Not a valid Action";

	public static final String LOG_IN_DISPLAY_NAME ="dispName";
	public static final String MISSING_VALUE = "Missing values are :";
	public static final String TO = "to";
	public static final String TITLE = "title";
	public static final String NOTIFICATION = "notification";
	public static final String DATA = "data";

	//CHAT
	public static final String ACCEPT_HEADER_KEY = "Accept";
	public static final String ACCEPT_HEADER_VALUE = "application/json";
	public static final String HEADERVALUE_HEADER_KEY = "headerValue";
	public static final String HEADERVALUE_HEADER_VALUE = "HeaderInformation";
	public static final String CHARACTERSET_UTF8 = "UTF8";
	public static final String CONTENT_TYPE_JSON = "application/json";
	public static final int OLAM_COMPANY_ID = 1;

	public static final String ACTIVE_STATUS = "Active";
	public static final String IN_ACTIVE_STATUS = "InActive";
	public static final String TENANT_ID = "tenant_id";
	public static final String TENANT_ID_PARAM = "tenant_id_param";
	public static final String TENANT_FILTER = "tenant_filter";
	public static final Object ENTITYLIST = "entityList";

	public static final String ISSUER = "OlamApplication";
	public static final String REFRESH_TOKEN = "refreshToken";
	
	public static final Object ENTITY_STRING = "entity";
	public static final String NUMBER = "number";
	public static final String CUSTOMER_ID = "customer_id";
	public static final String CONTRACT_ID = "contract_id";
	public static final String SHIPMENT_TYPE = "shipment_type";
	public static final String SHIPMENT_START_PERIOD = "shipment_start_period";
	public static final String SHIPMENT_END_PERIOD = "shipment_end_period";
	public static final String PAYMENT_TERM = "payment_term";
	public static final String ADVANCE_DATE = "advance_date";

	public static final String ADVANCE_REMINDER = "advance_reminder";
	public static final String DISCHARGE_TERMS = "discharge_terms";
	public static final String SPECIAL_TERMS = "special_terms";
	public static final String INCOTERMS_ID = "incoterms_id";
	public static final String DISCHARGE_PORT_ID = "discharge_port_id";
	public static final String TOTAL_QUANTITY = "total_quantity";

	public static final String SALES_PRICE = "sales_price";
	public static final String QUANTITY = "quantity";
	public static final String PACKING_TYPE = "packing_type";
	public static final String BAG_MARK = "bag_mark";
	public static final String CONTRACT_DATE = "contract_date";
	public static final String PRODUCT_TYPE_ID = "product_type_id";
	public static final String VM_CONTENT = "vm_content";

	public static final String CONTRACT_NUMBER = "contract_number";
	public static final String START_PERIOD = "start_period";
	public static final String END_PERIOD = "end_period";
	public static final String SHIPMENT_ID = "shipment_id";
	public static final String FIXATION_DATE = "fixation_date";
	public static final String LAYCON = "laycon";
	public static final String TOTAL_SHIPMENT_QUANTITY = "total_shipment_quantity";
	public static final String SHIPMENT_VESSEL_DETAIL_ID = "shipment_vessel_detail_id";
	public static final String PRODUCT_SHIPMENT_QUANTITY = "product_shipment_quantity";
	public static final String ARRIVAL_LOAD_PORT = "arrival_load_port";
	public static final String EXPECTED_DATE_COMPLETION = "expected_date_completion";
	public static final String ACTUAL_DATE_COMPLETION = "actual_date_completion";
	public static final String ACTUAL_DATE_ARRIVAL = "actual_date_arrival";
	public static final String ACTUAL_DATE_DEPARTURE = "actual_date_departure";
	public static final String ACTUAL_DATE_DEPARTURE_LOAD_PORT = "actual_date_departure_load_port";
	public static final String EXPECTED_DATE_ARRIVAL_DESTINATION_PORT = "expected_date_arrival_destination_port";
	public static final String TOTAL_LOAD_QUANTITY = "total_load_quantity";
	public static final String TOTAL_UNLOAD_QUANTITY = "total_unload_quantity";
	public static final String BALANCE_QUANTITY = "balance_quantity";
	public static final String ACTUAL_DATE_OF_BERTHING = "actual_date_of_berthing";
	public static final String IS_LOADING_TYPE = "is_loading_type";
	public static final String COUNTRY_ORIGIN_ID = "country_origin_id";
	public static final String LOADING_PORT_ID = "loading_port_id";
	public static final String LOADING_DISCHARGE_ID = "loading_discharge_id";
	public static final String SHIPMENT_VESSEL_LOADING_DETAIL_ID = "shipment_vessel_loading_detail_id";
	public static final String OC_REFERENCE_NUMBER = "oc_reference_number";
	public static final String FROM_CURRENCY = "from_currency";
	public static final String TO_CURRENCY = "to_currency";
	public static final String EXCHANGE_RATE = "exchange_rate";
	public static final String FROM_AMOUNT = "from_amount";
	public static final String TO_AMOUNT = "to_amount";
	public static final String COMMENTS = "comments";
	public static final String GRAND_BOL_TOTAL = "grand_bol_total";
	public static final String TOTAL_CURRENCY_COVER_AMOUNT = "total_currency_cover_amount";
	public static final String TOTAL_RECEIPT_AMOUNT = "total_receipt_amount";
	public static final String TOTAL_PAYMENT_AMOUNT = "total_payment_amount";
	public static final String IS_REMINDER = "is_reminder";
	public static final String IS_CURRENCY_COVER = "is_currency_cover";
	public static final String TOTAL_CREDIT_DEBIT_AMOUNT = "total_credit_debit_amount";
	public static final String BALANCE_AMOUNT = "balance_amount";
	public static final String TOTAL_BOL_QUANTITY = "total_bol_quantity";
	public static final String FINAL_DUE_AMOUNT = "final_due_amount";
	public static final String FINAL_PAYMENT_AMOUNT = "final_payment_amount";
	public static final String PAYMENT_ID = "payment_id";
	public static final String BOL_NUMBER = "bol_number";
	public static final String PRODUCT_NAME = "product_name";
	public static final String TOTAL_PRICE = "total_price";
	public static final String CREDIT_DEBIT_NOTE = "credit_debit_note";
	public static final String DOCUMENT_NO = "document_no";
	public static final String REASON = "reason";
	public static final String IS_SETTLED = "is_settled";
	public static final String PRICE = "price";
	public static final String FINAL_PAYMENT_DATE = "final_payment_date";
	public static final String TABLE_CITY = "city";
	public static final String PRODUCT_INFO_ID = "product_info_id";
	public static final String OLAM_CUSTOMER = "OLAM_CUSTOMER";
	public static final String OLAM_USER_READ_ONLY = "OLAM_USER_READ_ONLY";
	public static final String OLAM_CONTRACT_APPROVER = "OLAM_CONTRACT_APPROVER";
	public static final String LOAD_PORT = "LoadPort";
	public static final String PORT_TYPE_DISCHARGE = "discharge";
	public static final String PORT_TYPE_LOAD = "loading";
	public static final String OTHER_PAYMENT_TERMS = "other_payment_terms";
	public static final String OTHER_PORT_OF_DISCHARGE = "other_port_of_discharge";
	public static final String OTHER_INCOTERMS = "other_incoterms";
	public static final String OTHER_TO_CURRENCY = "other_to_currency";
	public static final String OTHER_FROM_CURRENCY = "other_from_currency";
	public static final String OTHER_COUNTRY = "other_country";
	public static final String SHIPPING_ADDRESS = "shipping_address";
	public static final String SHIPPING_CITY = "shipping_city";
	public static final String BILLING_ADDRESS = "billing_address";
	public static final String BILLING_CITY = "billing_city";
	public static final String PROFILE_URL = "profile_url";
	public static final String LANDLINE_NUMBER = "landline_number";
	public static final String PRIMARY_PHONE = "primary_phone";
	public static final String PRIMARY_EMAIL = "primary_email";
	public static final String PHONENUMBER = "phonenumber";
	public static final String CONTACT_NAME = "contact_name";
	public static final String PRODUCT_TOTAL_QUANTITY = "product_total_quantity";
	public static final String OTHER_CURRENCY = "other_currency";
	public static final String OTHER_PRODUCT_TYPE = "OTHER_PRODUCT_TYPE";
	public static final String TERMS = "terms";
	public static final String OTHER_PACKING_TYPE = "other_packing_type";
	public static final String OTHER_PRODUCT = "other_product";
	public static final String OTHER_LOADING_PORT = "other_loading_port";
	public static final String OTHER_LOADING_DISCHARGE_PORT = "other_loading_discharge_port";
	public static final String SEAGULL_PASSWORD = "ol@m$e@gu11";
	public static final String PAGE_NUMBER = "pageNumber";
	public static final String SHIPMENT_STATUS = "shipmentStatus";
	public static final String SHIPPING_COUNTRY = "shipping_country";
	public static final String BILLING_COUNTRY = "billing_country";
	public static final String SAME_SHIPPING_ADDRESS = "is_same_address";
	public static final String OLD_PASSWORD = "old_password";
	public static final String NEW_PASSWORD = "new_password";
	public static final String IDS = "ids";
	public static final String TOTAL_QUANTITY_PARAM = "totalQuantity";
	public static final String PRODUCT_INFO_PARAM = "productInfo";
	public static final String SHIPMENT_VESSEL_ID_PARAM = "shipmentVesselId";
	public static final String CREATED_BY_PARAM = "createdBy";
	public static final String COLUMN_TRANSFORMER_READ_AES_SALES_PRICE = "AES_DECRYPT("+SALES_PRICE+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_FINAL_DUE_AMOUNT = "AES_DECRYPT("+FINAL_DUE_AMOUNT+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_BALANCE_AMOUNT = "AES_DECRYPT("+BALANCE_AMOUNT+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_TOTAL_CREDIT_DEBIT_AMOUNT = "AES_DECRYPT("+TOTAL_CREDIT_DEBIT_AMOUNT+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_FROM_AMOUNT = "AES_DECRYPT("+FROM_AMOUNT+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_TO_AMOUNT = "AES_DECRYPT("+TO_AMOUNT+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_PRICE = "AES_DECRYPT("+PRICE+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_TOTAL_PRICE = "AES_DECRYPT("+TOTAL_PRICE+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_EXCHANGE_RATE = "AES_DECRYPT("+EXCHANGE_RATE+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_GRAND_BOL_TOTAL = "AES_DECRYPT("+GRAND_BOL_TOTAL+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_TOTAL_CURRENCY_COVER_AMOUNT = "AES_DECRYPT("+TOTAL_CURRENCY_COVER_AMOUNT+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_TOTAL_RECEIPT_AMOUNT = "AES_DECRYPT("+TOTAL_RECEIPT_AMOUNT+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_TOTAL_PAYMENT_AMOUNT = "AES_DECRYPT("+TOTAL_PAYMENT_AMOUNT+", '"+AES_KEY+"')";
	public static final String LANGUAGE_ID = "language_id";
	public static final String SEAGULL_CUSTOMER_DOCS = "seagull_customer_docs";
	public static final String DOCS = "docs";
	public static final String EMAIL_TEMPLATE_ID = "email_template_id";
	public static final String APP_URL = "app_url";
	public static final String EMAIL_NON_ZERO_AMOUNT_DUE = "EMAIL_NON_ZERO_AMOUNT_DUE";
	public static final String EMAIL_CONTRACT_NO = "contractNo";
	public static final String EMAIL_ADVANCE_AMOUNT = "advanceAmount";
	public static final String EMAIL_DUE_DATE = "dueDate";
	public static final String EMAIL_FINAL_DUE_DAILY = "EMAIL_FINAL_DUE_DAILY";
	public static final String EMAIL_CONTRACT_APPROVAL = "EMAIL_CONTRACT_APPROVAL";
	public static final String EMAIL_DUE_AMOUNT = "dueAmount";
	public static final String EMAIL_TOTAL_QUANTITY = "totalQuantity";
	public static final String EMAIL_BALANCE_QUANTITY = "balanceQuantity";
	public static final String EMAIL_LOADING_PORT = "loadingPort";
	public static final String EMAIL_DATE = "date";
	public static final String EMAIL_STATUS = "status";
	public static final String EMAIL_LOADING_QUANTITY = "loadingQuantity";
	public static final String EMAIL_UNLOADING_QUANTITY = "unloadingQuantity";
	public static final String EMAIL_LOADING_QUANTITY_TEMPLATE = "EMAIL_LOADING_QUANTITY_TEMPLATE";
	public static final String EMAIL_UNLOADING_QUANTITY_TEMPLATE = "EMAIL_UNLOADING_QUANTITY_TEMPLATE";
	public static final String EMAIL_SHIPMENT_STATUS_TEMPLATE = "EMAIL_SHIPMENT_STATUS_TEMPLATE";

	public static final String TABLE_LANGUAGE = "language";
	public static final String TABLE_EMAIL_TEMPLATE_VALUE = "email_template_value";
	public static final String TOTAL_COVERED = "totalCovered";
	public static final String REMAINING = "remaining";
	public static final String COLUMN_TRANSFORMER_READ_AES_TOTAL_COVERED = "AES_DECRYPT("+TOTAL_COVERED+", '"+AES_KEY+"')";
	public static final String COLUMN_TRANSFORMER_READ_AES_REMAINING = "AES_DECRYPT("+REMAINING+", '"+AES_KEY+"')";
	public static final String TABLE_SKU = "sku";
	public static final String SKU_ID = "sku_id";
	public static final String TABLE_PAYMENT_TYPE = "payment_type";

	public static final String RECEIPT_ID = "receipt_id";
	public static final String TABLE_RECEIPT_DETAIL = "receipt_detail";
	public static final String DRAFT = "Draft";
	public static final String APPROVED_AUDIT = "Approved";
	public static final String OLAM_USER_ROLE = "OLAM_USER";

	public static final String EMAIL_CUSTOMER_RESET = "EMAIL_CUSTOMER_RESET";
	public static final String advanceAmount = "advanceAmount";
	public static final String csvFields = "csvFields";
	public static final String creditDebitFields = "creditDebitFields";
	public static final String currencyCoverFields = "currencyCoverFields";
    public static final String receiptDetailsFields = "receiptDetailsFields";
    public static final String paymentDetailsFields = "paymentDetailsFields";
    public static final String productFields = "productFields";
    public static final String contractNumber = "contractNumber";
    public static final String auditValue = "auditValue";
    public static final String sectionName = "sectionName";

    public static final String CONTRACT_SECTION = "contract_section";
    public static final String PAYMENT_SECTION = "payment_section";
    public static final String DOCUMENT_ID = "document_id";
    public static final String DELETED_FLAG="deleted_flag";
	public static final String EMPTY_STRING = "";

	public static final String ERROR_INVALID_USER = "Invalid User";
	public static final String ERROR_ACCOUNT_DISABLED = "Disabled Account";
	public static final String USER_DET_EXPIRED = "The user detail has expired. please try again";
	public static final String ERROR_INVALID_PASSWORD = "Invalid Password";
	public static final String ACCESS_TOKEN = "accessToken";
	public static final String TOKEN_TYPE = "tokenType";
	public static final String EXPIRES_IN = "expires_in";
	public static final String AES = "AES";
	public static final String AGRI_SHA1PRNG = "SHA1PRNG";
	public static final String AGRI_SUN = "SUN";
	public static final String TABLE_OAUTH_TOKEN_DETAIL = "oauth_token_detail";
	public static final String USER_ID_FK = "users_id_fk";
	public static final String TOT_ATTEMPT = "tot_attempt";
	public static final String ERROR_ACCOUNT_LOCKED = "Account Locked";
	public static final String USER_GGUID = "user_gguid";
	public static final String CURRENT_ATTEMPT = "currentAttempt";
	public static final String OAUTH="oauth-private.key";
	public static final String TOKEN_EXPIRE_AT_STR = "exp_str";
	public static final String USER_NOT_FOUND = "User not found";
	public static final String MANDATORY_INPUT_MISSING = "Mandatory inputs are missing";
	public static final String USERNAME_SHOULD_BE_COHERENT_ID = "Username should be coherent id";
	public static final String OAUTH_ALGO_NAME="RSA";
}

