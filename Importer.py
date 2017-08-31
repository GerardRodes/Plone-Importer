# -*- coding: utf-8 -*-

try:
  # dexterity
  from plone.app.textfield.value import RichTextValue
except Exception as e:
  print str(e)
  pass
  
from plone.namedfile.file import NamedBlobImage
from plone.namedfile.file import NamedBlobFile
from Products.CMFPlone.utils import safe_unicode
from Products.CMFCore.utils import getToolByName
from Products.CMFCore.Expression import Expression, getExprContext
from plone.i18n.normalizer import idnormalizer
import xml.etree.ElementTree as ET
from DateTime import DateTime
from datetime import date, datetime
from dateutil import parser
from plone import api
import urllib, os, re, time, transaction, json, urllib2, pytz, sys, traceback


def dump(json_data):
  print json.dumps(json_data, indent=2)

class Importer:

  def __init__(self, xml_path, portal, folder_path = None, meta_type = None, tagname = 'item', fields_map = [], publish=True, import_as='dexterity'):
    """
      tagname: name of the tag at the xml which contains the objects to be imported
      fields_map: how fields at xml relate with dexterity fields
        {
          'xml': 'xml_attr_field',
          'dexterity': 'dexterity_fieldname',
          'archetype': 'archetype_fieldname',
          'filter': lambda value: value
        }
    """

    if folder_path and meta_type:
      self.mode = 'meta_type'
    else:
      self.mode = 'full_portal'

    self.import_as = import_as
    self.portal = portal
    self.catalog = portal.portal_catalog
    self.folder_path = folder_path if folder_path else '/'.join(self.portal.getPhysicalPath())
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


  def __call__(self):
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
    try:
      tree = ET.parse(self.xml_path, ET.XMLParser(encoding='utf-8'))
    except:
      tree = ET.parse(self.xml_path)
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
        if tag.text:
          output[tag.tag]['value'] = tag.text.strip()

      return output


    global n
    n = 0
    if self.mode == 'meta_type':
      for xml_item in root.findall(self.tagname):
        uid = xml_item.attrib.get('uid', None)
        loop_id = '_' + str(n)
        item = {'_uid': uid, '_loop_id': loop_id}
        for field in xml_item:
          item.update(process_tag(field))
        self.items[uid if uid else loop_id] = item
        n += 1

    elif self.mode == 'full_portal':

      def parse_xml_item(xml_item):
        global n
        n += 1
        self.happens(n)

        loop_id = '_' + str(n)
        item = {'_loop_id': loop_id}

        for key, value in xml_item.attrib.iteritems():
          item['_' + key] = value

        for field in xml_item:
          if field.tag != 'childs':
            item.update(process_tag(field))

        childs = xml_item.find('childs')
        if childs:
          item['_childs'] = []
          for child in list(childs):
            item['_childs'].append(parse_xml_item(child))

        if '_meta_type' in item:
          item['_type'] = {
            'Baner02': 'Banner',
            'ATDocument': 'Document',
            'ATEvent': 'Esdeveniment',
            'ATImage': 'Image',
            'ATBlob': 'File',
            'ATFile': 'File',
            'ATFolder': 'Folder',
            'ATLink': 'Link',
            'ATNewsItem': 'News Item',
            'ATTopic': 'Topic',
          }.get(item['_meta_type'], item['_meta_type'])

        self.items[item['_uid'] if '_uid' in item else loop_id] = item
        return item


      self.portal_tree = parse_xml_item(root[0])
      portal_tree_file = open(self.output_folder + '/portal_tree.json', 'w+')
      portal_tree_file.write(json.dumps(self.portal_tree, indent=2))
      portal_tree_file.close()


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

  def map_types(self, list_types):
    mapping = {
      'Event':'Esdeveniment',
      'Baner02': 'Banner',
    }

    new_list = []
    for old_type in list_types:
      if old_type in mapping.keys():
        new_list.append(mapping[old_type])
      else:
        new_list.append(old_type)
    return new_list


  def build_objects(self):

    portal_workflow = getToolByName(self.portal, 'portal_workflow')

    def process_string(new_item, item_info, data):

      if 'iterable' in data and data['iterable'].lower() in ("true", True, "yes"):
        return tuple([idnormalizer.normalize(item['value']) for item in data['value'] if item.get('value', None)])

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

      if self.import_as == 'archetype':
        return zope_dt

      if dt.utcoffset():
        dt = dt.replace(tzinfo=pytz.utc) + dt.utcoffset()
      else:
        dt = dt.replace(tzinfo=pytz.utc)

      return zope_dt if 'Date' in data['fieldname'] else dt


    references = []

    def process_reference(new_item, item_info, data):
      """
        References are delayed to be executed at the end to assure that all objects are created
      """
      references.append({'_new_item': new_item, 'item_info': item_info, 'data': data})
      return None


    def process_lines(new_item, item_info, data):
      return [item['value'] for item in data['value']]


    def process_file(new_item, item_info, data):
      file_path = '/'.join(self.xml_folder.split('/') + [file for file in data['value'].split('/') if file and file != '.'])
      if os.path.isfile(file_path):
        file_data = open(file_path, 'r').read()
        try:
          self.happens('\tTrying to create file: {path} ({size})'.format(path=file_path, size=os.path.getsize(file_path)))
          if 'image' in data['content_type']:
            return NamedBlobImage(data=file_data, contentType=data['content_type'])
          else:
            return NamedBlobFile(data=file_data, contentType=data['content_type'])  
        except Exception as e:
          exc_type, exc_obj, exc_tb = sys.exc_info()
          fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
          self.happens(
            "\tError %s at %s line %s\n\t%s" % 
            ( str(exc_type), str(fname), str(exc_tb.tb_lineno), str(e) )
          )
          pass


    def process_text(new_item, item_info, data):
      try:
        # self.import_as = dexterity|archetype
        if self.import_as == 'dexterity':
          rtv = RichTextValue(data['value'], data['content_type'], data['content_type'])
        else:
          rtv = data['value']
        return rtv.output if data['content_type'] == 'text/plain' else rtv
      except:
        return {'value': unicode(data['value']).encode('utf-8').strip(), 'mimetype': data['content_type']}


    def process_boolean(new_item, item_info, data):
      value = str(data['value']).lower()
      return value in ('true', '1', 'yes', 'si')


    def process_UID(new_item, item_info, data):
      item_data = self.items.get(data['value'], None)

      if not item_data:
        return None
      else:
        return item_data['_new_item'].UID()


    def process_integer(new_item, item_info, data):
      return int(data['value'])


    def process_tales(new_item, item_info, data):
      try:
        return Expression(data['value'])
      except:
        return Expression('string:'+data['value'])

    processors = {
      'string':    process_string,
      'datetime':  process_datetime,
      'reference': process_reference,
      'lines':     process_lines,
      'file':      process_file,
      'image':     process_file,
      'text':      process_text,
      'boolean':   process_boolean,
      'UID':       process_UID,
      'integer':   process_integer,
      'tales':     process_tales,
    }


    total = len(self.items)
    global current
    current = 1

    if self.mode == 'meta_type':
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
        item_info.update({'_new_item': new_item}) #Saved item object to reference later
        current += 1

        if current == 100: return

    elif self.mode == 'full_portal':

      def process_item(json_item, item):
        global current
        self.happens('{current}/{total} current item: {id} ({loop_id})'.format(current=current, total=total, id=json_item.get('_id', None), loop_id=json_item.get('_loop_id', None)))
        current += 1


        if '_childs' in json_item:
          self.happens('\tHas childs, processing...')
          for json_new_item in json_item['_childs']:
            new_item_id = json_new_item.get('_id', str(datetime.now())+str(current))
            self.happens('\tReaded new item with id {id}'.format(id=new_item_id))
            if new_item_id in item.keys():
              self.happens('\tItem exists, getting...')
              new_item = item.get(new_item_id)
              self.happens('\tGot -> id: {id}, uid:{uid}, path:{path}'.format(id=new_item.getId(), uid=new_item.UID(), path='/'.join(new_item.getPhysicalPath())))
            else:
              self.happens('\tItem ({type}) doesn\'t exists, creating...'.format(type=json_new_item.get('_type')))
              try:
                item.invokeFactory(json_new_item.get('_type'), new_item_id)
              except:
                t, v, tb = sys.exc_info()
                self.happens("{0}\n{1}\n{2}".format(t, v, tb))
                self.happens('\tNOT CREATED')
                continue

              new_item = item[new_item_id]
              self.happens('\tCreated {obj}'.format(obj=new_item))
              new_item.reindexObject()
              transaction.commit()
            # try:
            process_item(json_new_item, new_item)
            # except Exception as e:
            #   self.happens(str(e))
            #   pass

        for key, data in json_item.iteritems():
          if not key.startswith('_') and hasattr(item, 'getField'):
            # Processing fields
            processor_name = data.get('type', 'string')
            processor = processors.get(processor_name)

            if not processor:
              self.happens('\tWarning field {field} has an undefined processor {processor}, using string processor instead.'.format(field=data['fieldname'], processor=processor_name))
              processor = processors.get('string')

            field_value = processor(item, json_item, data)


            if key == 'immediatelyAddableTypes' or key == 'locallyAllowedTypes':
              field_value = self.map_types(field_value)

            try:
              self.happens('\tSetting field `{field}`({type}): ({type_2}){value}'.format(field=data['fieldname'], type=processor_name, type_2=type(field_value), value=str(field_value)[:100]))
            except:
              self.happens('\tSetting field `{field}`({type}): ({type_2})'.format(field=data['fieldname'], type=processor_name, type_2=type(field_value)))

            if isinstance(field_value, dict):
              item.getField(data['fieldname']).set(item, **field_value)
            else:
              item.getField(data['fieldname']).set(item, field_value)

        item_path = '/'.join(item.getPhysicalPath())
        item_brain = None
        results = self.catalog.searchResults({
          'path': {
            'query': item_path,
            'depth': 0
          },
          'getId': item.getId(),
        })
        if results:
          for brain in results:
             if brain.getPath() == item_path:
              item_brain = brain
              break

        if self.publish and item_brain and item_brain.get('review_state', None) and portal_workflow.getInfoFor(item, 'review_state') != 'published':
          portal_workflow.doActionFor(item, 'publish')
        elif '_review_state' in json_item:
        	for action in portal_workflow.listActions(object=item):
        		if 'id' in action and 'transition' in action and action['transition'].new_state_id == json_item['_review_state']:
        			portal_workflow.doActionFor(item, action['id'])
        else:
          item.reindexObject()

        self.items.get(json_item.get('_uid', json_item.get('_loop_id'))).update({'_new_item': item}) #Saved item object to reference later

      process_item(self.portal_tree, self.folder)




    self.happens('Objects creation finished.')
    if references:
      self.happens('Linking references.')
      total = len(references)
      current = 1
      for reference in references:
        self.happens('{current}/{total}'.format(current=current, total=total))

        new_item   = reference['_new_item']
        item_info  = reference['item_info']
        field_info = reference['data']

        raw_values = field_info['value'] if isinstance(field_info['value'], (tuple, list)) else (field_info['value'],)
        values = tuple()
        for field_child in raw_values:
          # Getting new UID from old UID
          values += (processors.get(field_child['type'], processors.get('UID'))(new_item, item_info, field_child),)

        fieldname = field_info['fieldname'](values) if callable(field_info['fieldname']) else field_info['fieldname']
        setattr(new_item, fieldname, value)
        new_item.reindexObject()
        current += 1


  def happens(self, msg):
    log_file = open(self.log_file.name, 'a')
    output = datetime.now().strftime('%H:%M:%S') + ' -- ' + str(msg) + '\n'
    log_file.write(output)
    log_file.close()
    try:
      print output
    except Exception as e:
      print "Error while printing but everything is fine, I guess...: {e}".format(e=str(e))
