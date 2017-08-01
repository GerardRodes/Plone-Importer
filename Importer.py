# -*- coding: utf-8 -*-

from plone.app.textfield.value import RichTextValue
from Products.CMFPlone.utils import safe_unicode
from Products.CMFCore.utils import getToolByName
from plone.i18n.normalizer import idnormalizer
from plone.namedfile.file import NamedBlobImage
from plone.namedfile.file import NamedBlobFile
import xml.etree.ElementTree as ET
from DateTime import DateTime
from datetime import date, datetime
from dateutil import parser
from plone import api
import urllib, os, re, time, transaction, json, urllib2, pytz


class Importer:

  def __init__(self, xml_path, portal, folder_path, meta_type = None, tagname = 'item', fields_map = [], publish=True):
    """
      tagname: name of the tag at the xml which contains the objects to be imported
      fields_map: how fields at xml relate with dexterity fields
        {'xml_attr_field': 'dexterity_fieldname', ...}
    """
    self.portal = portal
    self.folder_path = folder_path
    self.folder = None
    self.items = {}
    self.start = datetime.now()

    self.xml_path = xml_path
    self.xml_folder = '/'.join(self.xml_path.split('/')[:-1])
    self.meta_type = meta_type if meta_type else self.xml_path.split('/')[-1].split('.')[0]
    self.log_filename = 'log_' + self.start.strftime('%Y-%m-%d_%H-%M-%S') + '.txt'
    self.output_folder = '/tmp/importer/' + self.meta_type
    self.tagname = tagname

    self.fields_map = fields_map
    self.publish = publish

    self.create_log_file()
    self.happens('Initialized.')
    self.happens('Parsing XML...')
    self.parse_xml()
    self.happens('XML parsed, got {items} items.'.format(items=len(self.items)))
    self.check_target_folder()
    self.build_objects()
    self.happens('Finished in {time}'.format(time=datetime.now() - self.start))


  def create_log_file(self):
    if not os.path.exists(self.output_folder):
      os.makedirs(self.output_folder)

    self.log_file = open(self.output_folder + '/' + self.log_filename, 'w+')
    self.log_file.close()


  def parse_xml(self):
    tree = ET.parse(self.xml_path, ET.XMLParser(encoding='utf-8'))
    root = tree.getroot()

    def process_tag(tag):
      output = {}
      output[tag.tag] = {
        'fieldname': self.xml2dxt(tag.tag),
      }
      for key, value in tag.attrib.iteritems():
        output[tag.tag][key] = value

      if len(tag):
        for child in tag:
          output[tag.tag]['value'] = [process_tag(child)[child.tag] for child in tag]
      else:
        output[tag.tag]['value'] = tag.text.strip()

      return output


    n = 0
    for xml_item in root.findall(self.tagname):
      uid = xml_item.attrib.get('uid', None)
      loop_id = '_' + str(n)
      item = {'_uid': uid, '_loop_id': loop_id}
      for field in xml_item:
        item.update(process_tag(field))
      self.items[uid if uid else loop_id] = item
      n += 1


  def check_target_folder(self):
    current_folder = self.portal
    for folder in [folder for folder in self.folder_path.split('/') if folder][2:]:
      if folder in current_folder.keys():
        current_folder = getattr(current_folder, folder)
      else:
        self.happens("Folder {folder} doesn't exists, created.".format(folder=folder))
        current_folder = api.content.create(type='Folder', id=folder, title=folder, container=current_folder)

    transaction.commit()
    self.folder = current_folder


  def dxt2xml(self, dexterity_requested, field_value = None):
    """
      Given a dexterity fieldname wanted returns the corresponding fieldname on the XML
    """
    for field_relation in self.fields_map:
      fields_dexterity = field_relation['dexterity'] if isinstance(field_relation['dexterity'], (tuple, list)) else (field_relation['dexterity'],)
      fields_xml       = field_relation['xml'] if isinstance(field_relation['xml'], (tuple, list)) else (field_relation['xml'],)
      for field_dexterity in fields_dexterity:
        dexterity_fieldname = field_relation['dexterity'](field_value) if field_value and callable(field_relation['dexterity']) else field_relation['dexterity']
        if dexterity_fieldname == dexterity_requested:
          related_xml_fieldnames = tuple()
          for field_xml in fields_xml:
            related_xml_fieldnames += (field_xml(field_value) if field_value and callable(field_xml) else field_xml,)
          return related_xml_fieldnames

    return dexterity_requested


  def xml2dxt(self, xml_requested, field_value = None):
    """
      Given a xml attribute fieldname returns the corresponding dexterity fieldname
    """
    xml_requested = xml_requested(field_value) if callable(xml_requested) else xml_requested
    for field_relation in self.fields_map:
      fields_dexterity = field_relation['dexterity'] if isinstance(field_relation['dexterity'], (tuple, list)) else (field_relation['dexterity'],)
      fields_xml       = field_relation['xml'] if isinstance(field_relation['xml'], (tuple, list)) else (field_relation['xml'],)
      for field_xml in fields_xml:
        xml_fieldname = field_xml(field_value) if field_value and callable(field_xml) else field_xml
        if xml_fieldname == xml_requested:
          related_dexterity_fieldnames = tuple()
          for field_dexterity in fields_dexterity:
            related_dexterity_fieldnames += (field_dexterity(field_value) if field_value and callable(field_dexterity) else field_dexterity,)
          return related_dexterity_fieldnames

    return xml_requested


  def get_filter(self, fieldname_requested, field_value = None):
    """
      Returns the defined filter at fields_map for a given dexterity fieldname
    """
    fieldname_requested = fieldname_requested(field_value) if callable(fieldname_requested) else fieldname_requested
    for field_relation in self.fields_map:
      fields_dexterity = field_relation['dexterity'] if isinstance(field_relation['dexterity'], (tuple, list)) else (field_relation['dexterity'],)
      for field_dexterity in fields_dexterity:
        try:
          dexterity_fieldname = field_dexterity(field_value) if field_value and callable(field_dexterity) else field_dexterity
          if dexterity_fieldname == fieldname_requested:
            return field_relation.get('filter', None)
        except Exception as e:
          # self.happens('\t\tTried to apply filter but: ' + str(e) + '\n\t\t\tDon\'t worry, probably is not the filter you are looking for :)')
          pass

    return None


  def build_objects(self):

    references = []
    portal_workflow = getToolByName(self.portal, 'portal_workflow')

    def process_string(new_item, item_info, data):
      return data['value']


    def process_datetime(new_item, item_info, data):
      """
        Plone metadata dates indexes are a mess, i don't know in which classes are they using to store them
        but here are the diferent formats that appear at the catalog:
        start:        2017-08-01 09:00:00+02:00
        CreationDate: 2017-08-01T09:11:02+02:00
        created:      2017/08/01 09:11:2.231928 GMT+2
      """
      zope_dt = DateTime(data['value'])
      dt = zope_dt.asdatetime()
      if dt.utcoffset():
        return dt.replace(tzinfo=pytz.utc) + dt.utcoffset()
      else:
        return dt.replace(tzinfo=pytz.utc)


    def process_reference(new_item, item_info, data):
      """
        References are delayed to be executed at the end to assure that all objects are created
      """

      references.append({'_new_item_uid': item_info['_new_item_uid']}.update(data))
      return None


    def process_lines(new_item, item_info, data):
      return [item['value'] for item in data['value']]


    def process_file(new_item, item_info, data):
      # /tmp/import./files/CARTELL VETLLA1.pdf
      file_path = '/'.join(self.xml_folder.split('/') + [file for file in data['value'].split('/') if file and file != '.'])
      if os.path.isfile(file_path):
        file_data = open(file_path, 'r').read()
        try:
          self.happens('\tTrying to read file: {path}'.format(path=file_path))
          if 'image' in data['content_type']:
            return NamedBlobImage(data=file_data, contentType=data['content_type'])
          else:
            return NamedBlobFile(data=file_data, contentType=data['content_type'])
        except:
          self.happens('\tFailed')
          pass


    def process_text(new_item, item_info, data):
      return RichTextValue(data['value'], data['content_type'], data['content_type']).output


    def process_boolean(new_item, item_info, data):
      value = str(data['value']).lower()
      return value in ('true', '1', 'yes', 'si')


    processors = {
      'string':    process_string,
      'datetime':  process_datetime,
      'reference': process_reference,
      'lines':     process_lines,
      'file':      process_file,
      'text':      process_text,
      'boolean':   process_boolean,
    }


    total = len(self.items)
    current = 1
    for uid, item_info in self.items.iteritems():
      id = item_info.pop(self.dxt2xml('id'))['value']
      title = item_info.pop(self.dxt2xml('title'), id)['value']
      self.happens('{current}/{total} -> {id}'.format(current=current, total=total, id=id))

      if id in self.folder.keys():
        new_item = getattr(self.folder, id)
        self.happens('\tObject exists')
      else:
        new_item = api.content.create(type=self.meta_type, id=id, title=title, container=self.folder)
        self.happens('\tObject created')

      transaction.commit()
      item_info.update({'_new_item_uid': new_item.UID()})
      for field, field_info in item_info.iteritems():
        if not field.startswith('_'):
          dexterity_fieldname = field_info['fieldname']
          field_type = field_info.get('type', 'string')

          if not isinstance(dexterity_fieldname, (list, tuple)):
            dexterity_fieldname = (dexterity_fieldname,)

          for fieldname in dexterity_fieldname:
            value = processors.get(field_type, processors.get('string'))(new_item, item_info, field_info)
            if field_type not in processors:
              self.happens('\tWARNING: field type `{field_type}` not found, using `string` instead.'.format(field_type=field_type))
            value_filter = self.get_filter(fieldname, value)
            if value_filter:
              value = value_filter(value)
            fieldname = fieldname(value) if callable(fieldname) else fieldname
            try:
              self.happens('\tSetting field `{fieldname}`:`{type}` = `{value}`'.format(fieldname=fieldname, type=field_type, value=str(value.encode('utf-8') if hasattr(value, 'encode') else value)[:200]))
            except:
              self.happens('\tSetting field `{fieldname}`:`{type}`'.format(fieldname=fieldname, type=field_type))
              pass
            setattr(new_item, fieldname, value)

      if self.publish and portal_workflow.getInfoFor(new_item, 'review_state') != 'published':
        portal_workflow.doActionFor(new_item, 'publish')

      new_item.reindexObject()
      current += 1


  def happens(self, msg, log_type = 'event'):
    log_file = open(self.log_file.name, 'a')
    output = datetime.now().strftime('%H:%M:%S') + ' -- ' + str(msg) + '\n'
    log_file.write(output)
    log_file.close()
    try:
      print output
    except Exception as e:
      print "Error while printing but everything is fine, I guess...: {e}".format(e=str(e))
